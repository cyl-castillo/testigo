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
  predicateType = PREDICATE_TYPE,
  // Session-chain draft convention (predicate/session-chain.md): RFC 3339
  // exportedAt instead of testigo v0.1's epoch-ms exportedAtMs.
  exportedAtRfc3339 = false,
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
    predicateType,
    predicate: {
      caseId,
      project,
      ...(exportedAtRfc3339
        ? { exportedAt: "2026-07-17T12:00:00Z" }
        : { exportedAtMs: 1789000100000 }),
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
const BASE_SPECS = [
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
];
const BASE = ledger(BASE_SPECS);
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
const add = (name, description, pkt, expect, credit) =>
  vectors.push({ name, description, pkt, expect, credit });

const VALID_MINIMAL = packet({ entries: BASE.map(full), range: FULL_RANGE, head: HEAD });

add(
  "valid-minimal",
  "Full-ledger export, every event clean: all checks pass, every content hash recomputes.",
  VALID_MINIMAL,
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

add(
  "invalid-redaction-count",
  "Producer bug signed over: redactionCount does not equal the number of redacted entries (§2.3 — stubs are NOT redactions). Everything else verifies; the miscount misrepresents what was withheld. MUST fail §2.4 step 6.",
  packet({
    entries: caseEntries(),
    caseId: CASE,
    range: FULL_RANGE,
    head: HEAD,
    mutateStatement: (st) => {
      st.predicate.redactionCount = 3; // counts the stub as a redaction — the exact wrong guess §2.3 now forecloses
    },
  }),
  { valid: false, firstFailure: "redactionCount" },
);

// ---- signed-over mutation vectors (ported from Rul1an's donation) ----------
// Ported as generator code from the gist in cyl-castillo/testigo#1 so the
// corpus stays single-generator deterministic; the gist remains the
// reference. Each builds an INTERNALLY CONSISTENT statement (digest,
// linkage, seqs, range, redactionCount all repaired) and then pairs it with
// valid-minimal's signature — stale by construction, since the mutator holds
// no key. They catch a checker that trusts digest and linkage but skips or
// misorders the envelope check.

/// An internally consistent statement wearing valid-minimal's (stale) signature.
function staleSigned(entries, range, head) {
  const p = packet({ entries, range, head });
  p.envelope.signatures = VALID_MINIMAL.envelope.signatures;
  return p;
}

add(
  "invalid-injected-event-signature",
  "A self-consistent event is injected and digest, linkage, seq numbering, range and redactionCount are all repaired, so every non-signature check passes; the mutator holds no key, so the conformance-key signature is stale. MUST reject at signature — a checker that verifies digest and linkage but skips the envelope wrongly accepts.",
  (() => {
    const specs = [...BASE_SPECS.slice(0, 2), {
      caseId: CASE, kind: "tool_result", actor: "agent", turnId: "turn-1", termId: "t-1",
      payload: { tool: "Bash", excerpt: "injected", truncated: false },
    }, ...BASE_SPECS.slice(2)];
    const l = ledger(specs);
    return staleSigned(l.map(full), { fromSeq: 0, toSeq: 5, prevHashBefore: "genesis" }, { seq: 5, hash: l.at(-1).hash });
  })(),
  { valid: false, firstFailure: "signature" },
  "Rul1an (mutation donation, cyl-castillo/testigo#1)",
);

add(
  "invalid-duplicated-entry-signature",
  "An interior entry is duplicated with the chain re-linked around it — the completeness-attack sibling of injection: a checker relying on linkage continuity alone accepts a padded ledger. Signature stale; MUST reject at signature.",
  (() => {
    const specs = [...BASE_SPECS.slice(0, 4), BASE_SPECS[3], BASE_SPECS[4]];
    const l = ledger(specs);
    return staleSigned(l.map(full), { fromSeq: 0, toSeq: 5, prevHashBefore: "genesis" }, { seq: 5, hash: l.at(-1).hash });
  })(),
  { valid: false, firstFailure: "signature" },
  "Rul1an (mutation donation, cyl-castillo/testigo#1)",
);

add(
  "invalid-reserialized-line-signature",
  "One embedded line re-serialized to byte-different but semantically identical JSON, subject digest repaired to the new bytes. Guards byte-exact payload binding (§1.5): a checker that canonicalizes lines before hashing cannot tell the difference — the signature, bound to the pre-mutation bytes, can. MUST reject at signature.",
  (() => {
    const entries = BASE.map(full);
    const v = JSON.parse(entries[1].line);
    const { seq, ts, ...rest } = v;
    entries[1] = { line: JSON.stringify({ ts, seq, ...rest }), redacted: false }; // ts/seq swapped: same JSON semantics, different bytes
    return staleSigned(entries, FULL_RANGE, HEAD);
  })(),
  { valid: false, firstFailure: "signature" },
  "Rul1an (mutation donation, cyl-castillo/testigo#1)",
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
  add(
    "valid-timestamp-stripped",
    "The valid-timestamped packet with its timestamp member removed. Stripping loses the existence proof but forges nothing (§2.5): the packet MUST verify as valid with timestamp reported as absent — a verifier that fails a stripped packet is wrong.",
    { ...base },
    { valid: true, counts: { entries: 5, recomputed: 5, redacted: 0, stubs: 0 }, timestamp: "none" },
    "Rul1an (corpus cross, cyl-castillo/testigo#1)",
  );
  add(
    "invalid-timestamp-transplant",
    "A valid packet carrying the timestamp member of a DIFFERENT valid packet — token and declared imprint are internally consistent with each other, but imprint a different signature. The splice a relying party actually encounters: the packet stays valid, the timestamp MUST be reported as not matching (it must never migrate between packets).",
    (() => {
      const other = packet({ entries: BASE.map(full), range: FULL_RANGE, head: HEAD });
      return { ...other, timestamp: ts };
    })(),
    { valid: true, counts: { entries: 5, recomputed: 5, redacted: 0, stubs: 0 }, timestamp: "mismatch" },
    "Rul1an (corpus cross, cyl-castillo/testigo#1)",
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

// ---- session-chain subset (predicate/vectors) ------------------------------
// The same rules under the in-toto predicate proposal's conventions
// (predicateType URI + RFC 3339 exportedAt), so a checker of THAT predicate
// has bytes to run against — see predicate/session-chain.md. The subject
// shape mirrors testigo v0.1 for now; its redesign (produced artifacts +
// segment digest) is under discussion in in-toto/attestation#554.

const SC_OUT = path.join(HERE, "..", "predicate", "vectors");
const SC_TYPE = "https://in-toto.io/attestation/session-chain/v0.1";
const sc = { predicateType: SC_TYPE, exportedAtRfc3339: true };
const scVectors = [];
const scAdd = (name, description, pkt, expect) =>
  scVectors.push({ name, description, pkt, expect });

scAdd(
  "sc-valid-minimal",
  "Full-ledger export under the session-chain predicate conventions: all checks pass.",
  packet({ ...sc, entries: BASE.map(full), range: FULL_RANGE, head: HEAD }),
  { valid: true, counts: { entries: 5, recomputed: 5, redacted: 0, stubs: 0 }, timestamp: "none" },
);
scAdd(
  "sc-valid-redacted-stub",
  "Case export with redactions and a stub; redactionCount counts redacted entries only (stubs are pruning, not redaction).",
  packet({ ...sc, entries: caseEntries(), caseId: CASE, range: FULL_RANGE, head: HEAD }),
  { valid: true, counts: { entries: 5, recomputed: 2, redacted: 2, stubs: 1 }, timestamp: "none" },
);
scAdd(
  "sc-invalid-linkage",
  "Producer bug signed over: broken chain linkage at a stub.",
  (() => {
    const entries = caseEntries();
    entries[2].stub.prevHash = "d".repeat(64);
    return packet({ ...sc, entries, caseId: CASE, range: FULL_RANGE, head: HEAD });
  })(),
  { valid: false, firstFailure: "linkage" },
);
scAdd(
  "sc-invalid-redaction-count",
  "Producer bug signed over: redactionCount counts the stub as a redaction (3 instead of 2).",
  packet({
    ...sc,
    entries: caseEntries(),
    caseId: CASE,
    range: FULL_RANGE,
    head: HEAD,
    mutateStatement: (st) => {
      st.predicate.redactionCount = 3;
    },
  }),
  { valid: false, firstFailure: "redactionCount" },
);
// Migration guards (Rul1an, testigo#1 part 2): the two fields that make
// session-chain a distinct predicate must be GUARDED, not just instantiated —
// these negatives are signature-valid on purpose (only the key holder can
// produce them), so they separate a checker that enforces the migration from
// one that silently ignores it.
scAdd(
  "sc-invalid-predicate-type",
  "Signature-valid statement carrying the PARENT testigo v0.1 predicate type URI. A session-chain checker MUST reject it (spec §5: verifiers reject predicate types they don't implement); a checker that ignores predicateType passes it and is thereby caught.",
  packet({ ...sc, predicateType: PREDICATE_TYPE, entries: BASE.map(full), range: FULL_RANGE, head: HEAD }),
  { valid: false, firstFailure: "predicateType" },
);
scAdd(
  "sc-invalid-exported-at",
  "Signature-valid statement carrying exportedAtMs (epoch ms, the parent convention) instead of RFC 3339 exportedAt. A session-chain checker MUST reject it; a checker that ignores the field convention passes it and is thereby caught.",
  packet({ ...sc, exportedAtRfc3339: false, entries: BASE.map(full), range: FULL_RANGE, head: HEAD }),
  { valid: false, firstFailure: "exportedAt" },
);

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
  manifest.vectors.push({
    file,
    description: v.description,
    expect: v.expect,
    ...(v.credit ? { credit: v.credit } : {}),
  });
}
fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`wrote ${vectors.length} vectors + manifest.json to ${OUT}`);

fs.mkdirSync(SC_OUT, { recursive: true });
const scManifest = {
  suite: "session-chain-draft-conformance",
  spec: "predicate/session-chain.md (draft) — predicateType " + SC_TYPE,
  keyId: KEY_ID,
  // What a checker of THIS predicate must enforce on top of the packet
  // rules — the migration-guard negatives test exactly these. BINDING on
  // what this corpus asserts; INFORMATIVE as a checker input: a checker
  // derives its expectations from the spec text and cross-checks this block
  // against that reading — one that obeys the block alone is back to
  // trusting the producer's declaration, the exact trust the negatives
  // exist to remove.
  enforce: { predicateType: SC_TYPE, exportedAt: "rfc3339" },
  note: "Instantiates the DRAFT in-toto session-chain predicate (RFC 3339 exportedAt). Sessions here produced no artifacts, so subjects carry the session's own content-addressed descriptor per the draft's subject rule. Same published throwaway key as the main suite. Migration-guard negatives credit: Rul1an (cyl-castillo/testigo#1).",
  vectors: scVectors.map((v) => {
    const file = `${v.name}.proofpack.json`;
    fs.writeFileSync(path.join(SC_OUT, file), JSON.stringify(v.pkt, null, 2) + "\n");
    return { file, description: v.description, expect: v.expect };
  }),
};
fs.writeFileSync(path.join(SC_OUT, "manifest.json"), JSON.stringify(scManifest, null, 2) + "\n");
console.log(`wrote ${scVectors.length} session-chain vectors + manifest.json to ${SC_OUT}`);
