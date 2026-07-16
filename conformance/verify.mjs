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

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/// Verify one packet per §2.4. Returns:
///   { valid, firstFailure, counts: {entries, recomputed, redacted, stubs},
///     timestamp: "none" | "declared" | "mismatch", keyId }
/// firstFailure ∈ format | keyid | signature | payload | digest | linkage | contentHash
export function verifyPacket(pkt) {
  const fail = (code) => ({ valid: false, firstFailure: code });

  // 1. Format.
  if (pkt.format !== "testigo-proofpack/v0.1") return fail("format");

  // 2. keyid = sha256 of the embedded raw public key.
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
  const events = st.predicate?.events ?? [];
  const want = st.subject?.[0]?.digest?.sha256 ?? "";
  if (sha256hex(Buffer.from(JSON.stringify(events), "utf8")) !== want) return fail("digest");

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
      const idx = e.line.lastIndexOf('"hash":"');
      const recomputed = sha256hex(Buffer.from(e.line.slice(0, idx) + '"hash":""}', "utf8"));
      if (recomputed !== hash) return fail("contentHash");
      counts.recomputed++;
    }
    prev = hash;
  }

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

// ---- runner -----------------------------------------------------------------

const HERE = path.dirname(new URL(import.meta.url).pathname);
const arg = process.argv[2];

if (arg) {
  const result = verifyPacket(JSON.parse(fs.readFileSync(arg, "utf8")));
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid ? 0 : 1);
}

const dir = path.join(HERE, "vectors");
const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8"));
let failures = 0;
for (const v of manifest.vectors) {
  const got = verifyPacket(JSON.parse(fs.readFileSync(path.join(dir, v.file), "utf8")));
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
console.log(failures ? `\n${failures} vector(s) failed` : `\nall ${manifest.vectors.length} vectors pass`);
process.exit(failures ? 1 : 0);
