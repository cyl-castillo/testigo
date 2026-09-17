#!/usr/bin/env node
// Execute the HTML's actual script, including WebCrypto and load/render, in a
// minimal DOM. No copied verification implementation and no browser dependency.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { verifyPacket } from "./verify.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "../verifier/testigo-verifier.html"), "utf8");
class Element {
  children = [];
  style = {};
  classList = { add() {}, remove() {} };
  textContent = "";
  set innerHTML(value) { this.children = []; this.html = value; }
  get innerHTML() { return this.html; }
  addEventListener() {}
  appendChild(child) { this.children.push(child); }
  append(...children) { this.children.push(...children); }
}
const elements = new Map();
const document = {
  getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
  createElement() { return new Element(); },
};
const context = vm.createContext({ document, crypto: crypto.webcrypto, TextEncoder, TextDecoder, atob, Blob,
  URL: { createObjectURL() { return "blob:test"; } } });
vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
let count = 0;
for (const dir of ["vectors", "../predicate/vectors"]) {
  const manifest = JSON.parse(fs.readFileSync(path.join(here, dir, "manifest.json")));
  for (const vector of manifest.vectors) {
    const text = fs.readFileSync(path.join(here, dir, vector.file), "utf8");
    context.inputFile = { text: async () => text };
    await vm.runInContext("load(inputFile)", context);
    const checks = document.getElementById("checks").children;
    const failures = checks.filter(e => e.className === "check fail").map(e => e.textContent);
    // Browser implements Testigo, so default reference behavior applies to
    // the explicit draft corpus (including its wrong-parent-type negative).
    const expected = manifest.enforce ? verifyPacket(JSON.parse(text)) : vector.expect;
    assert.equal(failures.length === 0, expected.valid, `${vector.file}: ${failures.join("; ")}`);
    if (["payloadType", "statementType", "predicateType", "predicate", "range", "sequence", "entry", "events", "subject"].includes(expected.firstFailure))
      assert.ok(failures.some(s => s.includes(expected.firstFailure + ":")), `${vector.file}: targeted check`);
    if (expected.counts?.redacted) assert.ok(checks.some(e => e.textContent.includes(`${expected.counts.redacted} event(s) redacted`)));
    if (expected.counts?.stubs) assert.ok(checks.some(e => e.textContent.includes(`${expected.counts.stubs} out-of-case event(s)`)));
    if (expected.timestamp === "mismatch") assert.ok(checks.some(e => e.className === "check warn" && e.textContent.includes("imprint does not match")));
    count++;
  }
}
console.log(`browser script: ${count} vectors pass (WebCrypto + rendering; Testigo profile)`);
