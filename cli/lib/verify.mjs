// Packet verifier (SPEC.md §2.4 + §2.5) — the CLI's own implementation.
// The conformance suite's verify.mjs is a SEPARATE copy on purpose: the
// suite is the oracle this implementation is tested against, so they must
// not share code (cli/test.mjs runs this verifier over every vector and
// compares verdicts with the manifest).

import crypto from "node:crypto";

const TESTIGO_TYPE = "https://github.com/cyl-castillo/testigo/attestation/v0.1";
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isHash = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const isSeq = (v) => Number.isSafeInteger(v) && v >= 0;

// Validate the signed structure before using it. Unknown predicate/ledger
// members and event kinds remain additive; entry wrappers retain schema oneOf.
function checkStructure(st) {
  if (!isObject(st)) return "payload";
  if (st._type !== "https://in-toto.io/Statement/v1") return "statementType";
  if (st.predicateType !== TESTIGO_TYPE) return "predicateType";
  const p = st.predicate;
  if (!isObject(p)) return "predicate";
  if (typeof p.project !== "string" || typeof p.generator !== "string" || !Number.isInteger(p.exportedAtMs)) return "predicate";
  if (p.caseId !== undefined && p.caseId !== null && typeof p.caseId !== "string") return "predicate";
  if (p.ledgerHead !== undefined && (!isObject(p.ledgerHead) ||
      (p.ledgerHead.seq != null && !Number.isInteger(p.ledgerHead.seq)) ||
      (p.ledgerHead.hash != null && typeof p.ledgerHead.hash !== "string"))) return "predicate";
  if (p.redactionCount !== undefined &&
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

/// Returns { valid, firstFailure, counts, timestamp, keyId } —
/// Failure codes include profile/structure checks (payloadType, statementType,
/// predicateType, predicate, subject, events, entry, range, sequence), then
/// keyid, signature, digest, linkage, contentHash, redactionCount and context.
/// timestamp ∈ none | declared | mismatch (declared ≠ verified: no CMS here).
export function verifyPacket(pkt) {
  const fail = (code) => ({ valid: false, firstFailure: code });

  if (!isObject(pkt) || pkt.format !== "testigo-proofpack/v0.1") return fail("format");

  if (!isObject(pkt.envelope) || typeof pkt.publicKey !== "string" ||
      typeof pkt.envelope.payload !== "string" || !Array.isArray(pkt.envelope.signatures)) return fail("payload");
  if (pkt.envelope.payloadType !== "application/vnd.in-toto+json") return fail("payloadType");
  const pubRaw = Buffer.from(pkt.publicKey ?? "", "base64");
  const keyId = sha256hex(pubRaw);
  const sigEntry = pkt.envelope?.signatures?.[0] ?? {};
  if (sigEntry.keyid !== keyId) return fail("keyid");

  const payload = Buffer.from(pkt.envelope.payload ?? "", "base64");
  const type = pkt.envelope.payloadType ?? "";
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} ${type} ${payload.length} `, "utf8"),
    payload,
  ]);
  let sigOk = false;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pubRaw]),
      format: "der",
      type: "spki",
    });
    sigOk = crypto.verify(null, pae, key, Buffer.from(sigEntry.sig ?? "", "base64"));
  } catch {}
  if (!sigOk) return fail("signature");

  let st;
  try {
    st = JSON.parse(payload.toString("utf8"));
  } catch {
    return fail("payload");
  }
  const structureFailure = checkStructure(st);
  if (structureFailure) return fail(structureFailure);
  const events = st.predicate.events;
  if (sha256hex(Buffer.from(JSON.stringify(events), "utf8")) !== (st.subject?.[0]?.digest?.sha256 ?? ""))
    return fail("digest");

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
      if (sha256hex(Buffer.from(e.line.slice(0, idx) + '"hash":""}', "utf8")) !== hash)
        return fail("contentHash");
      counts.recomputed++;
    }
    prev = hash;
  }

  if ((st.predicate?.redactionCount ?? 0) !== counts.redacted) return fail("redactionCount");

  // §2.6 process context: optional fields, well-formed when present; the
  // session window must equal the first/last non-stub line's ts.
  const pred = st.predicate ?? {};
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const nonEmpty = (v) => typeof v === "string" && v.length > 0;
  if (pred.provider !== undefined) {
    const p = pred.provider;
    if (!isObj(p) || !isObj(p.harness) || !nonEmpty(p.harness.name) || !nonEmpty(p.harness.version)) return fail("processContext");
    if (p.agent !== undefined && !isObj(p.agent)) return fail("processContext");
    if (p.languageModels !== undefined && !(Array.isArray(p.languageModels) && p.languageModels.every(isObj))) return fail("processContext");
  }
  if (pred.contextArtifacts !== undefined) {
    if (!Array.isArray(pred.contextArtifacts)) return fail("processContext");
    for (const a of pred.contextArtifacts) {
      if (!isObj(a) || (Object.hasOwn(a, "uri") === Object.hasOwn(a, "data") || !nonEmpty(a.uri ?? a.data))) return fail("processContext");
      if (a.digest !== undefined && !(isObj(a.digest) && /^[0-9a-f]{64}$/.test(a.digest.sha256 ?? ""))) return fail("processContext");
      if (a.tags !== undefined && !(Array.isArray(a.tags) && a.tags.every(nonEmpty))) return fail("processContext");
    }
  }
  if (pred.owner !== undefined && !nonEmpty(pred.owner)) return fail("processContext");
  if ((pred.startTimestamp !== undefined) !== (pred.endTimestamp !== undefined)) return fail("timestamps");
  if (pred.startTimestamp !== undefined) {
    const rfc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
    if (!rfc.test(pred.startTimestamp) || !rfc.test(pred.endTimestamp)) return fail("timestamps");
    const ts = events.filter((e) => typeof e.line === "string").map((e) => JSON.parse(e.line).ts);
    if (!ts.length || Date.parse(pred.startTimestamp) !== ts[0] || Date.parse(pred.endTimestamp) !== ts.at(-1)) return fail("timestamps");
  }

  let timestamp = "none";
  const tsp = pkt.timestamp;
  if (tsp && tsp.type === "rfc3161") {
    const sigDigest = sha256hex(Buffer.from(sigEntry.sig, "base64"));
    let token = null;
    try {
      token = Buffer.from(tsp.token ?? "", "base64");
    } catch {}
    const ok =
      sigDigest === String(tsp.messageImprint ?? "").toLowerCase() &&
      token !== null &&
      token.includes(Buffer.from(sigDigest, "hex"));
    timestamp = ok ? "declared" : "mismatch";
  }

  return { valid: true, firstFailure: null, counts, timestamp, keyId, statement: st };
}
