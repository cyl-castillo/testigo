#!/usr/bin/env node
// Regression guards beyond verifier-vs-manifest agreement. In particular,
// independently verify that semantic negatives really are signed over.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyPacket } from "./verify.mjs";
import { verifyPacket as cliVerify } from "../cli/lib/verify.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const draft = { predicateType: "https://in-toto.io/attestation/session-chain/v0.1" };
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
let signed = 0;
for (const dir of ["vectors", "../predicate/vectors"]) {
  const manifest = JSON.parse(fs.readFileSync(path.join(here, dir, "manifest.json")));
  for (const v of manifest.vectors) {
    if (!v.description.startsWith("Signed-over isolated")) continue;
    const p = JSON.parse(fs.readFileSync(path.join(here, dir, v.file)));
    const payload = Buffer.from(p.envelope.payload, "base64");
    const type = p.envelope.payloadType;
    const pae = Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]);
    const pub = crypto.createPublicKey({ format: "der", type: "spki", key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(p.publicKey, "base64"),
    ]) });
    assert.ok(crypto.verify(null, pae, pub, Buffer.from(p.envelope.signatures[0].sig, "base64")), `${v.file}: signature must verify`);
    const st = JSON.parse(payload);
    if (["sequence", "range", "predicateType", "statementType", "payloadType"].includes(v.expect.firstFailure)) {
      assert.equal(st.subject[0].digest.sha256, sha(JSON.stringify(st.predicate.events)), `${v.file}: digest must match`);
      if (st.predicate.range) {
        let previous = st.predicate.range.prevHashBefore;
        for (const e of st.predicate.events) {
          const event = e.stub ?? JSON.parse(e.line);
          assert.equal(event.prevHash, previous, `${v.file}: linkage must hold`);
          previous = event.hash;
        }
      }
      for (const e of st.predicate.events) if (e.line && !e.redacted) {
        const parsed = JSON.parse(e.line);
        assert.equal(sha(e.line.slice(0, e.line.lastIndexOf('"hash":"')) + '"hash":""}'), parsed.hash, `${v.file}: content must recompute`);
      }
    }
    signed++;
  }
}
const read = file => JSON.parse(fs.readFileSync(path.join(here, file)));
const sc = read("../predicate/vectors/sc-valid-minimal.proofpack.json");
assert.equal(verifyPacket(sc).firstFailure, "predicateType");
assert.equal(cliVerify(sc).firstFailure, "predicateType");
assert.ok(verifyPacket(sc, draft).valid, "explicit URI alone enables the whole draft profile");
assert.equal(verifyPacket(read("../predicate/vectors/sc-invalid-exported-at.proofpack.json"), draft).firstFailure, "exportedAt");
assert.equal(verifyPacket(read("vectors/valid-minimal.proofpack.json"), draft).firstFailure, "predicateType");
assert.equal(verifyPacket(sc, { predicateType: "unknown" }).firstFailure, "profile");
for (const malformed of [null, [], {}, { format: "testigo-proofpack/v0.1" }, { format: "testigo-proofpack/v0.1", envelope: null }]) {
  assert.equal(verifyPacket(malformed).valid, false);
  assert.equal(cliVerify(malformed).valid, false);
}
for (const name of ["demo", "fixy-deploy-verification"]) {
  const packet = read(`../examples/${name}.proofpack.json`);
  assert.ok(verifyPacket(packet).valid, `${name}: reference compatibility`);
  assert.ok(cliVerify(packet).valid, `${name}: CLI compatibility`);
}
console.log(`validation: ${signed} isolated semantic negatives have valid signatures; profile boundaries, malformed inputs and existing examples pass`);
