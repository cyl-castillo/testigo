// Regression coverage for byte-exact event hashes, using the real ledger,
// packet verifiers and the standalone browser verifier's script.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

import { append, ledgerPath, readLedger, verifyChain } from "../cli/lib/ledger.mjs";
import { exportPacket } from "../cli/lib/export.mjs";
import { verifyPacket as cliVerify } from "../cli/lib/verify.mjs";
import { verifyPacket as referenceVerify } from "./verify.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const html = fs.readFileSync(path.join(HERE, "../verifier/testigo-verifier.html"), "utf8");
const browserScript = html.match(/<script>([\s\S]*?)<\/script>/)[1];

async function browserChecks(packet) {
  // This DOM adapter collects the verifier's actual status messages. Web
  // Crypto is real; markup behavior is outside this hash regression's scope.
  const elements = new Map();
  const element = () => ({
    style: {}, children: [], textContent: "", innerHTML: "", className: "",
    addEventListener() {}, classList: { add() {}, remove() {} },
    append(...children) { this.children.push(...children); },
    appendChild(child) { this.children.push(child); },
  });
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement: element,
  };
  const context = vm.createContext({ document, crypto: crypto.webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, atob, btoa, URL, Blob });
  vm.runInContext(browserScript, context);
  await context.load({ text: async () => JSON.stringify(packet) });
  return elements.get("checks").children;
}

test("CLI and reference verifiers retain all conformance verdicts", () => {
  for (const dir of [path.join(HERE, "vectors"), path.join(HERE, "../predicate/vectors")]) {
    const manifest = read(path.join(dir, "manifest.json"));
    for (const vector of manifest.vectors) {
      const packet = read(path.join(dir, vector.file));
      const reference = referenceVerify(packet, manifest.enforce ?? {});
      assert.equal(reference.valid, vector.expect.valid, `reference: ${vector.file}`);
      if (!vector.expect.valid) assert.equal(reference.firstFailure, vector.expect.firstFailure, vector.file);
      // The generic CLI intentionally does not enforce session-chain migration.
      const cliExpected = vector.expect.valid || ["predicateType", "exportedAt"].includes(vector.expect.firstFailure);
      const cli = cliVerify(packet);
      assert.equal(cli.valid, cliExpected, `CLI: ${vector.file}`);
      if (!cliExpected) assert.equal(cli.firstFailure, vector.expect.firstFailure, vector.file);
      for (const result of [reference, cli]) if (result.valid) {
        if (vector.expect.counts) assert.deepEqual(result.counts, vector.expect.counts, vector.file);
        if (vector.expect.timestamp) assert.equal(result.timestamp, vector.expect.timestamp, vector.file);
      }
    }
  }
});

test("browser checks content hashes without discarding bytes", async () => {
  const files = [
    "valid-minimal", "valid-redacted-stub", "valid-hash-whitespace", "valid-payload-hash",
    "invalid-member-after-hash", "invalid-payload-after-hash", "invalid-escaped-payload-after-hash", "invalid-hash-trailing-whitespace",
  ];
  for (const name of files) {
    const checks = await browserChecks(read(path.join(HERE, "vectors", `${name}.proofpack.json`)));
    const messages = checks.map((check) => check.textContent);
    assert.ok(messages.some((text) => text.includes("Signature valid")), `${name}: signature must pass`);
    assert.ok(messages.some((text) => text.includes("Subject digest matches")), `${name}: digest must pass`);
    assert.ok(messages.some((text) => text.includes("Hash chain linkage intact")), `${name}: linkage must pass`);
    const failures = checks.filter((check) => check.className === "check fail");
    if (name.startsWith("invalid-")) {
      assert.equal(failures.length, 1, name);
      assert.match(failures[0].textContent, /1 event\(s\) failed content hash recomputation/, name);
    } else {
      assert.equal(failures.length, 0, name);
    }
  }
});

test("ledger verification and export reject unsealed suffixes", async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "testigo-hash-test-"));
  const oldData = process.env.XDG_DATA_HOME;
  const oldConfig = process.env.XDG_CONFIG_HOME;
  process.env.XDG_DATA_HOME = path.join(sandbox, "data");
  process.env.XDG_CONFIG_HOME = path.join(sandbox, "config");
  t.after(() => {
    if (oldData === undefined) delete process.env.XDG_DATA_HOME; else process.env.XDG_DATA_HOME = oldData;
    if (oldConfig === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = oldConfig;
    // sandbox is the absolute, freshly-created temporary directory above.
    fs.rmSync(sandbox, { recursive: true, force: true });
  });
  for (const name of ["member-after-hash", "payload-after-hash", "escaped-payload-after-hash", "hash-trailing-whitespace"]) {
    const root = path.join(sandbox, name);
    const packet = read(path.join(HERE, "vectors", `invalid-${name}.proofpack.json`));
    const statement = JSON.parse(Buffer.from(packet.envelope.payload, "base64"));
    const lines = statement.predicate.events.map((entry) => entry.line);
    fs.mkdirSync(path.dirname(ledgerPath(root)), { recursive: true });
    fs.writeFileSync(ledgerPath(root), lines.join("\n") + "\n");
    assert.equal(verifyChain(root).ok, false, name);
    assert.equal(verifyChain(root).brokenAtSeq, 1, name);
    await assert.rejects(exportPacket(root, { outDir: path.join(sandbox, "out"), owner: "hash-test" }), /ledger chain broken at seq 1/, name);
  }

  for (const name of ["valid-hash-whitespace", "valid-payload-hash"]) {
    const root = path.join(sandbox, name);
    const packet = read(path.join(HERE, "vectors", `${name}.proofpack.json`));
    const statement = JSON.parse(Buffer.from(packet.envelope.payload, "base64"));
    fs.writeFileSync(ledgerPath(root), statement.predicate.events.map((entry) => entry.line).join("\n") + "\n");
    assert.equal(verifyChain(root).ok, true, name);
  }

  // A malformed hash must fail rather than matching a verifier's sentinel.
  for (const hash of [null, "", "a".repeat(63), "A".repeat(64), 123]) {
    const root = path.join(sandbox, "malformed-hash");
    fs.writeFileSync(ledgerPath(root), JSON.stringify({ seq: 0, prevHash: "genesis", hash }) + "\n");
    assert.equal(verifyChain(root).ok, false, `malformed hash: ${hash}`);
  }

  const root = path.join(sandbox, "clean");
  fs.mkdirSync(root);
  append(root, { caseId: "test:hash", kind: "tool_result", actor: "agent", payload: { hash: "nested value", excerpt: 'literal "hash":"value" — café' } });
  assert.equal(verifyChain(root).ok, true);
  const output = await exportPacket(root, { outDir: path.join(sandbox, "out"), owner: "hash-test" });
  const packet = read(output.path);
  assert.equal(cliVerify(packet).valid, true);
  assert.equal(referenceVerify(packet).valid, true);
  assert.equal(readLedger(root).lines.length, 1);
});
