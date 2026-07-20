// Packet verifier (SPEC.md §2.4 + §2.5) — the CLI's own implementation.
// The conformance suite's verify.mjs is a SEPARATE copy on purpose: the
// suite is the oracle this implementation is tested against, so they must
// not share code (cli/test.mjs runs this verifier over every vector and
// compares verdicts with the manifest).

import crypto from "node:crypto";

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/// Returns { valid, firstFailure, counts, timestamp, keyId } —
/// firstFailure ∈ format | keyid | signature | payload | digest | linkage | contentHash;
/// timestamp ∈ none | declared | mismatch (declared ≠ verified: no CMS here).
export function verifyPacket(pkt) {
  const fail = (code) => ({ valid: false, firstFailure: code });

  if (pkt.format !== "testigo-proofpack/v0.1") return fail("format");

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
  const events = st.predicate?.events ?? [];
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
      const idx = e.line.lastIndexOf('"hash":"');
      if (sha256hex(Buffer.from(e.line.slice(0, idx) + '"hash":""}', "utf8")) !== hash)
        return fail("contentHash");
      counts.recomputed++;
    }
    prev = hash;
  }

  if ((st.predicate?.redactionCount ?? 0) !== counts.redacted) return fail("redactionCount");

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
