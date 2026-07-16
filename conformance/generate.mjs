#!/usr/bin/env node
// Deterministic generator for the Testigo conformance vectors (spec §2.4).
//
// Every vector isolates ONE verification step: the packet is built so that
// all checks before the targeted one pass, and the targeted one fails (or,
// for the valid-* vectors, everything passes). "Producer bug" vectors
// (invalid-digest, invalid-linkage, invalid-content-hash) are signed OVER
// the defect — the signature verifies, the defect is inside — because that
// is exactly the laundering a verifier must catch.
//
// Signing uses a WELL-KNOWN throwaway key (seed = 0x42 × 32, published in
// the README). Packets signed with it prove nothing and never will; the key
// exists so vectors are reproducible byte-for-byte: run this script twice
// and the output is identical. Ed25519 is deterministic, timestamps are
// fixed constants, and there is no randomness anywhere.
//
// The two timestamp vectors need a one-time real RFC 3161 token (fixtures/
// timestamp-token.b64). Without it they are skipped and this script prints
// how to fetch one; because signatures are deterministic, a fetched token
// stays valid across regenerations until the payload itself changes.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const OUT = path.join(HERE, "vectors");
const TOKEN_FIXTURE = path.join(HERE, "fixtures", "timestamp-token.b64");

const FORMAT = "testigo-proofpack/v0.1";
const PREDICATE_TYPE = "https://github.com/cyl-castillo/testigo/attestation/v0.1";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const TSA_URL = "https://freetsa.org/tsr";

// ---- well-known conformance key ------------------------------------------
const SEED = Buffer.alloc(32, 0x42);
const PKCS8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  SEED,
]);
const PRIV = crypto.createPrivateKey({ key: PKCS8, format: "der", type: "pkcs8" });
// Raw public key = last 32 bytes of the SPKI DER.
const PUB_RAW = crypto
  .createPublicKey(PRIV)
  .export({ format: "der", type: "spki" })
  .subarray(-32);

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const KEY_ID = sha256hex(PUB_RAW);

// ---- ledger construction (§1.2, §1.5) -------------------------------------

/// Serialize an event with `hash` as the final member, exactly as the spec
/// hashes it: compact JSON, member order preserved, non-ASCII unescaped.
function makeLine(fields) {
  const unhashed = JSON.stringify({ ...fields, hash: "" });
  const hash = sha256hex(Buffer.from(unhashed, "utf8"));
  return { line: JSON.stringify({ ...fields, hash }), hash };
}

/// Build a chained ledger from event specs. Fixed timestamps keep the whole
/// suite deterministic.
function ledger(specs) {
  let prev = "genesis";
  const out = [];
  specs.forEach((s, seq) => {
    const fields = {
      seq,
      ts: 1789000000000 + seq * 1000,
      caseId: s.caseId,
      ...(s.turnId ? { turnId: s.turnId } : {}),
      kind: s.kind,
      ...(s.termId ? { termId: s.termId } : {}),
      actor: s.actor,
      payload: s.payload,
      prevHash: prev,
    };
    const { line, hash } = makeLine(fields);
    out.push({ ...fields, line, hash });
    prev = hash;
  });
  return out;
}

// ---- packet construction (§2.1–§2.3) --------------------------------------

function pae(type, payload) {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} ${type} ${payload.length} `, "utf8"),
    payload,
  ]);
}

/// Assemble, sign and wrap a packet. `mutate` hooks let a vector plant its
/// defect at the right layer (before or after signing).
function packet({
  entries,
  caseId = null,
  project = "conformance",
  range,
  head,
  mutateStatement, // producer bug: defect signed over
  mutatePacket, // transport tamper: defect after signing
}) {
  const redactionCount = entries.filter((e) => e.redacted).length;
  const eventsBody = JSON.stringify(entries);
  const statement = {
    _type: STATEMENT_TYPE,
    subject: [
      { name: caseId ?? "ledger", digest: { sha256: sha256hex(Buffer.from(eventsBody, "utf8")) } },
    ],
    predicateType: PREDICATE_TYPE,
    predicate: {
      caseId,
      project,
      exportedAtMs: 1789000100000,
      generator: "testigo-conformance/1.0",
      range,
      ledgerHead: head,
      redactionCount,
      events: entries,
    },
  };
  if (mutateStatement) mutateStatement(statement);
  const payload = Buffer.from(JSON.stringify(statement), "utf8");
  const sig = crypto.sign(null, pae(PAYLOAD_TYPE, payload), PRIV);
  const pkt = {
    format: FORMAT,
    envelope: {
      payloadType: PAYLOAD_TYPE,
      payload: payload.toString("base64"),
      signatures: [{ keyid: KEY_ID, sig: sig.toString("base64") }],
    },
    publicKey: PUB_RAW.toString("base64"),
  };
  if (mutatePacket) mutatePacket(pkt, sig);
  return pkt;
}

const full = (ev) => ({ line: ev.line, redacted: false });
const stub = (ev) => ({ stub: { seq: ev.seq, prevHash: ev.prevHash, hash: ev.hash, kind: ev.kind } });
/// Per-protocol redaction: the LINE changes, seq/prevHash/hash stay intact.
const redactLine = (ev, from, to) => ({ line: ev.line.replace(from, to), redacted: true });

// ---- the base ledger shared by most vectors -------------------------------

const CASE = "jira:CONF-1";
const BASE = ledger([
  { caseId: CASE, kind: "case_link", actor: "system", termId: "t-1", payload: {} },
  {
    caseId: CASE,
    kind: "prompt",
    actor: "human",
    turnId: "turn-1",
    termId: "t-1",
    payload: { prompt: "deploy the release — api key sk-conformance0000000000000000 must not leak" },
  },
  { caseId: "term:t-2", kind: "prompt", actor: "human", turnId: "turn-x", termId: "t-2", payload: { prompt: "unrelated work" } },
  {
    caseId: CASE,
    kind: "approval_decision",
    actor: "human",
    turnId: "turn-1",
    termId: "t-1",
    payload: { approvalId: "a-1", tool: "Bash", decision: "allow", reason: "reviewed" },
  },
  {
    caseId: CASE,
    kind: "turn_end",
    actor: "agent",
    turnId: "turn-1",
    termId: "t-1",
    payload: { filesChanged: [] },
  },
]);
const HEAD = { seq: BASE.at(-1).seq, hash: BASE.at(-1).hash };
const FULL_RANGE = { fromSeq: 0, toSeq: 4, prevHashBefore: "genesis" };

/// The redacted/stub case export used by several vectors: the prompt's
/// secret auto-redacted, the approval manually redacted, the out-of-case
/// prompt pruned to a stub.
function caseEntries() {
  const manual = (ev) => {
    const v = JSON.parse(ev.line);
    const fields = { ...v, payload: { redacted: "manual" } };
    delete fields.hash;
    return { line: JSON.stringify({ ...fields, hash: ev.hash }), redacted: true };
  };
  return [
    full(BASE[0]),
    redactLine(BASE[1], "sk-conformance0000000000000000", "[REDACTED:api-key]"),
    stub(BASE[2]),
    manual(BASE[3]),
    full(BASE[4]),
  ];
}

// ---- vectors ---------------------------------------------------------------

const vectors = [];
const add = (name, description, pkt, expect) =>
  vectors.push({ name, description, pkt, expect });

add(
  "valid-minimal",
  "Full-ledger export, every event clean: all checks pass, every content hash recomputes.",
  packet({ entries: BASE.map(full), range: FULL_RANGE, head: HEAD }),
  { valid: true, counts: { entries: 5, recomputed: 5, redacted: 0, stubs: 0 }, timestamp: "none" },
);

add(
  "valid-redacted-stub",
  "Case export with one auto-redacted event, one manually redacted event (payload replaced, hash kept) and one out-of-case stub. Valid; redacted and stub entries MUST be visibly reported (§2.4 step 7).",
  packet({ entries: caseEntries(), caseId: CASE, range: FULL_RANGE, head: HEAD }),
  { valid: true, counts: { entries: 5, recomputed: 2, redacted: 2, stubs: 1 }, timestamp: "none" },
);

add(
  "valid-unknown-kind",
  "Ledger containing an event kind no verifier knows. Verifiers MUST ignore unknown kinds (§1.7): the chain still verifies.",
  (() => {
    const l = ledger([
      { caseId: CASE, kind: "prompt", actor: "human", turnId: "turn-1", termId: "t-1", payload: { prompt: "hi" } },
      { caseId: CASE, kind: "quantum_leap", actor: "system", payload: { novel: true, note: "kinds are open — hashing is content-agnostic" } },
      { caseId: CASE, kind: "turn_end", actor: "agent", turnId: "turn-1", termId: "t-1", payload: {} },
    ]);
    return packet({
      entries: l.map(full),
      range: { fromSeq: 0, toSeq: 2, prevHashBefore: "genesis" },
      head: { seq: 2, hash: l.at(-1).hash },
    });
  })(),
  { valid: true, counts: { entries: 3, recomputed: 3, redacted: 0, stubs: 0 }, timestamp: "none" },
);

add(
  "invalid-format",
  "Unknown packet format string. MUST be rejected at §2.4 step 1.",
  (() => {
    const p = packet({ entries: BASE.map(full), range: FULL_RANGE, head: HEAD });
    p.format = "testigo-proofpack/v9.9";
    return p;
  })(),
  { valid: false, firstFailure: "format" },
);

add(
  "invalid-keyid",
  "Embedded signature keyid does not equal sha256 of the embedded public key. MUST fail §2.4 step 2 (the signature itself is fine — the keyid is the lie).",
  packet({
    entries: BASE.map(full),
    range: FULL_RANGE,
    head: HEAD,
    mutatePacket: (p) => {
      p.envelope.signatures[0].keyid = "0".repeat(64);
    },
  }),
  { valid: false, firstFailure: "keyid" },
);

add(
  "invalid-signature",
  "Signature bytes corrupted after signing (transport tamper). MUST fail §2.4 step 3.",
  packet({
    entries: BASE.map(full),
    range: FULL_RANGE,
    head: HEAD,
    mutatePacket: (p, sig) => {
      const bad = Buffer.from(sig);
      bad[0] ^= 0xff;
      p.envelope.signatures[0].sig = bad.toString("base64");
    },
  }),
  { valid: false, firstFailure: "signature" },
);

add(
  "invalid-digest",
  "Producer bug signed over: the subject digest does not match the packed events. The signature VERIFIES — the defect is inside the signed statement. MUST fail §2.4 step 4.",
  packet({
    entries: BASE.map(full),
    range: FULL_RANGE,
    head: HEAD,
    mutateStatement: (st) => {
      st.subject[0].digest.sha256 = "f".repeat(64);
    },
  }),
  { valid: false, firstFailure: "digest" },
);

add(
  "invalid-linkage",
  "Producer bug signed over: a stub's prevHash does not chain from the previous entry (signature and subject digest both verify). MUST fail §2.4 step 5.",
  (() => {
    const entries = caseEntries();
    entries[2].stub.prevHash = "d".repeat(64);
    return packet({ entries, caseId: CASE, range: FULL_RANGE, head: HEAD });
  })(),
  { valid: false, firstFailure: "linkage" },
);

add(
  "invalid-content-hash",
  "Producer bug signed over: a non-redacted line's content was altered but its stored hash (and the chain around it) kept — linkage holds, recomputation does not. MUST fail §2.4 step 6.",
  (() => {
    const entries = BASE.map(full);
    entries[1].line = entries[1].line.replace("deploy the release", "deploy something else");
    return packet({ entries, range: FULL_RANGE, head: HEAD });
  })(),
  { valid: false, firstFailure: "contentHash" },
);

// ---- timestamp vectors (need the one-time token fixture) -------------------

if (fs.existsSync(TOKEN_FIXTURE)) {
  const token = Buffer.from(fs.readFileSync(TOKEN_FIXTURE, "utf8").trim(), "base64");
  const base = packet({ entries: BASE.map(full), project: "conformance-ts", range: FULL_RANGE, head: HEAD });
  const imprint = sha256hex(Buffer.from(base.envelope.signatures[0].sig, "base64"));
  if (!token.includes(Buffer.from(imprint, "hex"))) {
    console.error(
      `fixtures/timestamp-token.b64 does not imprint this packet's signature.\n` +
        `The payload changed — fetch a fresh token for digest ${imprint} (see README) and re-run.`,
    );
    process.exit(1);
  }
  const ts = {
    type: "rfc3161",
    tsaUrl: TSA_URL,
    hashAlg: "sha256",
    messageImprint: imprint,
    token: token.toString("base64"),
  };
  add(
    "valid-timestamped",
    "Valid packet carrying a real RFC 3161 token over its signature (§2.5). Verifiers SHOULD report it as declared — and MUST NOT claim cryptographic token verification without a CMS stack.",
    { ...base, timestamp: ts },
    { valid: true, counts: { entries: 5, recomputed: 5, redacted: 0, stubs: 0 }, timestamp: "declared" },
  );
  add(
    "invalid-timestamp",
    "Same packet, but the declared messageImprint is not sha256 of this signature. The packet stays VALID (§2.4 steps 1–6 pass; the timestamp sits outside the envelope) — but the timestamp MUST be reported as not matching, never as a proof.",
    { ...base, timestamp: { ...ts, messageImprint: "a".repeat(64) } },
    { valid: true, counts: { entries: 5, recomputed: 5, redacted: 0, stubs: 0 }, timestamp: "mismatch" },
  );
} else {
  const base = packet({ entries: BASE.map(full), project: "conformance-ts", range: FULL_RANGE, head: HEAD });
  const imprint = sha256hex(Buffer.from(base.envelope.signatures[0].sig, "base64"));
  console.error(
    `NOTE: skipping the two timestamp vectors — fixtures/timestamp-token.b64 is missing.\n` +
      `Fetch one (single network call, sends only this digest):\n` +
      `  openssl ts -query -digest ${imprint} -sha256 -cert -out req.tsq\n` +
      `  curl -H 'Content-Type: application/timestamp-query' --data-binary @req.tsq ${TSA_URL} -o resp.tsr\n` +
      `  base64 -w0 resp.tsr > fixtures/timestamp-token.b64\n`,
  );
}

// ---- write everything ------------------------------------------------------

fs.mkdirSync(OUT, { recursive: true });
const manifest = {
  suite: "testigo-conformance",
  spec: "testigo-proofpack/v0.1 — SPEC.md §2.4/§2.5",
  keyId: KEY_ID,
  note: "Signed with the PUBLISHED throwaway conformance key (seed 0x42×32) — these packets prove nothing and never will.",
  vectors: [],
};
for (const v of vectors) {
  const file = `${v.name}.proofpack.json`;
  fs.writeFileSync(path.join(OUT, file), JSON.stringify(v.pkt, null, 2) + "\n");
  manifest.vectors.push({ file, description: v.description, expect: v.expect });
}
fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`wrote ${vectors.length} vectors + manifest.json to ${OUT}`);
