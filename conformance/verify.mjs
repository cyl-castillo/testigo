#!/usr/bin/env node
// Reference verifier for Testigo proof packets (spec §2.4 + §2.5), used as
// the conformance-suite runner: it verifies every vector in vectors/ and
// compares the outcome against manifest.json expectations.
//
// It is deliberately written from the spec, not shared with generate.mjs —
// two independent code paths (plus the HTML verifier and the Rust reference
// implementation) have to agree on every vector for the suite to pass.
//
// Usage:
//   node verify.mjs                     # run the suite against vectors/
//   node verify.mjs some.proofpack.json # verify one packet, print the result

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const TESTIGO_TYPE = "https://github.com/cyl-castillo/testigo/attestation/v0.1";
const SESSION_CHAIN_TYPE = "https://in-toto.io/attestation/session-chain/v0.1";
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isHash = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const isSeq = (v) => Number.isSafeInteger(v) && v >= 0;

// Validate the signed structure before using it. Unknown predicate/ledger
// members and event kinds remain additive; entry wrappers retain schema oneOf.
function checkStructure(st, sessionChain = false) {
  if (!isObject(st)) return "payload";
  if (st._type !== "https://in-toto.io/Statement/v1") return "statementType";
  if (st.predicateType !== (sessionChain ? SESSION_CHAIN_TYPE : TESTIGO_TYPE)) return "predicateType";
  const p = st.predicate;
  if (!isObject(p)) return "predicate";
  if (sessionChain) {
    // Date.parse alone normalizes impossible dates (e.g. February 30).
    const t = p.exportedAt;
    if (typeof t !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(t) ||
        !Number.isFinite(Date.parse(t)) || new Date(t).toISOString().slice(0, 19) !== t.slice(0, 19)) return "exportedAt";
  } else if (typeof p.project !== "string" || typeof p.generator !== "string" || !Number.isInteger(p.exportedAtMs)) return "predicate";
  if ((p.project !== undefined && typeof p.project !== "string") ||
      (p.generator !== undefined && typeof p.generator !== "string") ||
      (p.caseId !== undefined && p.caseId !== null && typeof p.caseId !== "string")) return "predicate";
  if (p.ledgerHead !== undefined && (!isObject(p.ledgerHead) ||
      (p.ledgerHead.seq != null && !Number.isInteger(p.ledgerHead.seq)) ||
      (p.ledgerHead.hash != null && typeof p.ledgerHead.hash !== "string"))) return "predicate";
  if ((sessionChain || p.redactionCount !== undefined) &&
      (!Number.isInteger(p.redactionCount) || p.redactionCount < 0)) return "redactionCount";
  if (!Array.isArray(st.subject) || !st.subject.length || st.subject.some((s) =>
      !isObject(s) || typeof s.name !== "string" || !isObject(s.digest) ||
      !Object.keys(s.digest).length || Object.values(s.digest).some((d) => typeof d !== "string"))) return "subject";
  if (!Array.isArray(p.events)) return "events";
  const r = p.range;
  if (!isObject(r) || !isSeq(r.fromSeq) || !isSeq(r.toSeq) || r.toSeq < r.fromSeq ||
      p.events.length !== r.toSeq - r.fromSeq + 1 ||
      (r.fromSeq === 0 ? r.prevHashBefore !== "genesis" : !isHash(r.prevHashBefore))) return "range";
  for (let i = 0; i < p.events.length; i++) {
    const e = p.events[i];
    if (!isObject(e)) return "entry";
    let v;
    if (Object.hasOwn(e, "line")) {
      if (typeof e.line !== "string" || typeof e.redacted !== "boolean" ||
          Object.keys(e).some((k) => !["line", "redacted"].includes(k))) return "entry";
      try { v = JSON.parse(e.line); } catch { return "entry"; }
      if (!isObject(v) || !Number.isInteger(v.ts) || typeof v.caseId !== "string" ||
          typeof v.kind !== "string" || !["human", "agent", "system"].includes(v.actor) || !isObject(v.payload) ||
          ["turnId", "termId", "sessionId"].some((k) => v[k] !== undefined && typeof v[k] !== "string")) return "entry";
    } else {
      if (!isObject(e.stub) || Object.keys(e).some((k) => k !== "stub")) return "entry";
      v = e.stub;
      // kind is optional on legacy stubs, as in the published schema.
      if (v.kind !== undefined && typeof v.kind !== "string") return "entry";
    }
    if (!isSeq(v.seq) || v.seq !== r.fromSeq + i) return "sequence";
    if (!isHash(v.hash) || !(v.prevHash === "genesis" || isHash(v.prevHash))) return "entry";
  }
  return null;
}

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/// Verify one packet per §2.4. Returns:
///   { valid, firstFailure, counts: {entries, recomputed, redacted, stubs},
///     timestamp: "none" | "declared" | "mismatch", keyId }
/// Structural failure codes: payloadType, statementType, predicateType,
/// predicate, subject, events, entry, range, sequence; draft-only: exportedAt.
/// `enforce.predicateType` explicitly selects one of the two implemented
/// profiles. Default: Testigo. Selecting session-chain ALWAYS enables all its
/// rules, regardless of the legacy manifest's informative exportedAt flag.
export function verifyPacket(pkt, enforce = {}) {
  const fail = (code) => ({ valid: false, firstFailure: code });

  // 1. Format.
  if (!isObject(pkt) || pkt.format !== "testigo-proofpack/v0.1") return fail("format");

  // 2. keyid = sha256 of the embedded raw public key.
  if (!isObject(pkt.envelope) || typeof pkt.publicKey !== "string" ||
      typeof pkt.envelope.payload !== "string" || !Array.isArray(pkt.envelope.signatures)) return fail("payload");
  if (pkt.envelope.payloadType !== "application/vnd.in-toto+json") return fail("payloadType");
  const pubRaw = Buffer.from(pkt.publicKey ?? "", "base64");
  const keyId = sha256hex(pubRaw);
  const sigEntry = pkt.envelope?.signatures?.[0] ?? {};
  if (sigEntry.keyid !== keyId) return fail("keyid");

  // 3. Ed25519 over the DSSE pre-authentication encoding.
  const payload = Buffer.from(pkt.envelope.payload ?? "", "base64");
  const type = pkt.envelope.payloadType ?? "";
  const paeBuf = Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} ${type} ${payload.length} `, "utf8"),
    payload,
  ]);
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    pubRaw,
  ]);
  let sigOk = false;
  try {
    const key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });
    sigOk = crypto.verify(null, paeBuf, key, Buffer.from(sigEntry.sig ?? "", "base64"));
  } catch {
    sigOk = false;
  }
  if (!sigOk) return fail("signature");

  // 4. Statement parses; subject digest matches the packed events.
  let st;
  try {
    st = JSON.parse(payload.toString("utf8"));
  } catch {
    return fail("payload");
  }
  // Explicit selection only; the packet never selects its own profile.
  if (!isObject(enforce) || (enforce.predicateType !== undefined && ![TESTIGO_TYPE, SESSION_CHAIN_TYPE].includes(enforce.predicateType))) return fail("profile");
  const sessionChain = enforce.predicateType === SESSION_CHAIN_TYPE;
  const structureFailure = checkStructure(st, sessionChain);
  if (structureFailure) return fail(structureFailure);
  const events = st.predicate.events;
  const digest = sha256hex(Buffer.from(JSON.stringify(events), "utf8"));
  if (sessionChain && st.predicate.evidence !== undefined) {
    const evidence = st.predicate.evidence;
    if (!isObject(evidence) || typeof evidence.name !== "string" || evidence.digest?.sha256 !== digest) return fail("digest");
    // Repeated segment descriptors in subject must agree too.
    if (st.subject.some((s) => s.name === evidence.name && s.digest.sha256 !== digest)) return fail("digest");
  } else if ((sessionChain ? st.subject : [st.subject[0]]).some((s) => s.digest.sha256 !== digest)) return fail("digest");

  // 5 + 6. Linkage across every entry; content recompute for clean lines.
  let prev = st.predicate?.range?.prevHashBefore ?? "genesis";
  const counts = { entries: events.length, recomputed: 0, redacted: 0, stubs: 0 };
  for (const e of events) {
    let prevHash, hash;
    if (typeof e.line === "string") {
      let v;
      try {
        v = JSON.parse(e.line);
      } catch {
        return fail("linkage");
      }
      ({ prevHash, hash } = v);
      if (e.redacted) counts.redacted++;
    } else if (e.stub) {
      ({ prevHash, hash } = e.stub);
      counts.stubs++;
    } else {
      return fail("linkage");
    }
    if (prevHash !== prev) return fail("linkage");
    if (typeof e.line === "string" && !e.redacted) {
      if (!/"hash":"[0-9a-f]{64}"}$/.test(e.line)) return fail("contentHash");
      const idx = e.line.lastIndexOf('"hash":"');
      const recomputed = sha256hex(Buffer.from(e.line.slice(0, idx) + '"hash":""}', "utf8"));
      if (recomputed !== hash) return fail("contentHash");
      counts.recomputed++;
    }
    prev = hash;
  }

  // 6b. Declared redaction count must match the entries (§2.3: stubs are
  // pruning, not redaction — a signed-over miscount misrepresents what was
  // withheld).
  if ((st.predicate?.redactionCount ?? 0) !== counts.redacted) return fail("redactionCount");

  // 6c. Process context (§2.6): every field optional; present ones must be
  // well-formed, and the declared session window must equal what the hashed
  // lines carry (the one claim among them a verifier can actually check).
  const pc = checkProcessContext(st.predicate ?? {}, events);
  if (pc) return fail(pc);

  // 8. Timestamp (§2.5): informative — declared or mismatching, never "verified".
  let timestamp = "none";
  const tsp = pkt.timestamp;
  if (tsp && tsp.type === "rfc3161") {
    const sigDigest = sha256hex(Buffer.from(sigEntry.sig, "base64"));
    let token = null;
    try {
      token = Buffer.from(tsp.token ?? "", "base64");
    } catch {
      token = null;
    }
    const ok =
      sigDigest === String(tsp.messageImprint ?? "").toLowerCase() &&
      token !== null &&
      token.includes(Buffer.from(sigDigest, "hex"));
    timestamp = ok ? "declared" : "mismatch";
  }

  return { valid: true, firstFailure: null, counts, timestamp, keyId };
}

const RFC3339_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/// §2.6 checks. Returns a failure code or null. `processContext` = a present
/// field is malformed; `timestamps` = the declared window does not equal the
/// first/last non-stub line's `ts` (or only one bound is declared).
export function checkProcessContext(pred, events) {
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const nonEmpty = (v) => typeof v === "string" && v.length > 0;
  if (pred.provider !== undefined) {
    const p = pred.provider;
    if (!isObj(p) || !isObj(p.harness) || !nonEmpty(p.harness.name) || !nonEmpty(p.harness.version))
      return "processContext";
    if (p.agent !== undefined && !isObj(p.agent)) return "processContext";
    if (p.languageModels !== undefined && !(Array.isArray(p.languageModels) && p.languageModels.every(isObj)))
      return "processContext";
  }
  if (pred.contextArtifacts !== undefined) {
    if (!Array.isArray(pred.contextArtifacts)) return "processContext";
    for (const a of pred.contextArtifacts) {
      if (!isObj(a)) return "processContext";
      if (Object.hasOwn(a, "uri") === Object.hasOwn(a, "data") || !nonEmpty(a.uri ?? a.data)) return "processContext";
      if (a.digest !== undefined && !(isObj(a.digest) && /^[0-9a-f]{64}$/.test(a.digest.sha256 ?? "")))
        return "processContext";
      if (a.tags !== undefined && !(Array.isArray(a.tags) && a.tags.every(nonEmpty))) return "processContext";
    }
  }
  if (pred.owner !== undefined && !nonEmpty(pred.owner)) return "processContext";
  const hasStart = pred.startTimestamp !== undefined;
  const hasEnd = pred.endTimestamp !== undefined;
  if (hasStart !== hasEnd) return "timestamps";
  if (hasStart) {
    if (!RFC3339_Z.test(pred.startTimestamp) || !RFC3339_Z.test(pred.endTimestamp)) return "timestamps";
    const ts = events.filter((e) => typeof e.line === "string").map((e) => JSON.parse(e.line).ts);
    if (!ts.length) return "timestamps";
    if (Date.parse(pred.startTimestamp) !== ts[0] || Date.parse(pred.endTimestamp) !== ts.at(-1)) return "timestamps";
  }
  return null;
}

// ---- runner (only when executed directly — verifyPacket stays importable) ---

function runManifest(dir, label) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
  let failures = 0;
  for (const v of manifest.vectors) {
    const got = verifyPacket(JSON.parse(fs.readFileSync(path.join(dir, v.file), "utf8")), manifest.enforce ?? {});
    const problems = [];
    if (got.valid !== v.expect.valid) problems.push(`valid: got ${got.valid}, want ${v.expect.valid}`);
    if (!v.expect.valid && got.firstFailure !== v.expect.firstFailure)
      problems.push(`firstFailure: got ${got.firstFailure}, want ${v.expect.firstFailure}`);
    if (v.expect.counts)
      for (const [k, want] of Object.entries(v.expect.counts))
        if (got.counts?.[k] !== want) problems.push(`counts.${k}: got ${got.counts?.[k]}, want ${want}`);
    if (v.expect.timestamp && got.timestamp !== v.expect.timestamp)
      problems.push(`timestamp: got ${got.timestamp}, want ${v.expect.timestamp}`);
    if (problems.length) {
      failures++;
      console.log(`FAIL  ${v.file}\n      ${problems.join("\n      ")}`);
    } else {
      console.log(`ok    ${v.file}`);
    }
  }
  console.log(failures ? `\n${failures} ${label} vector(s) failed\n` : `\nall ${manifest.vectors.length} ${label} vectors pass\n`);
  return failures;
}

function runSuite() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const args = process.argv.slice(2);
  let enforce = {};
  if (args[0] === "--profile") {
    const profile = args[1];
    if (!["testigo", "session-chain"].includes(profile) || args.length !== 3) {
      console.error("usage: verify.mjs [--profile testigo|session-chain] packet.json");
      process.exit(2);
    }
    enforce = { predicateType: profile === "session-chain" ? SESSION_CHAIN_TYPE : TESTIGO_TYPE };
    args.splice(0, 2);
  }
  const arg = args[0];

  if (arg) {
    const result = verifyPacket(JSON.parse(fs.readFileSync(arg, "utf8")), enforce);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }

  let failures = runManifest(path.join(here, "vectors"), "conformance");
  // The session-chain draft subset (predicate/vectors) exercises the same
  // rules under the proposed in-toto predicate conventions.
  const scDir = path.join(here, "..", "predicate", "vectors");
  if (fs.existsSync(path.join(scDir, "manifest.json"))) failures += runManifest(scDir, "session-chain");
  process.exit(failures ? 1 : 0);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) runSuite();
