// Regression coverage for the actual two-command CLI review/sign workflow.
// No network; all ledgers, git defaults, keys, and output stay in a sandbox.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { append, ledgerPath, readLedger } from "./lib/ledger.mjs";
import { keyFile, prepareStatement } from "./lib/export.mjs";
import { verifyPacket } from "./lib/verify.mjs";
import { verifyPacket as verifyIndependent } from "../conformance/verify.mjs";

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "testigo-review-test-"));
process.env.XDG_DATA_HOME = path.join(sandbox, "data");
process.env.XDG_CONFIG_HOME = path.join(sandbox, "config");
process.env.GIT_CONFIG_GLOBAL = path.join(sandbox, "gitconfig");
process.env.GIT_CONFIG_NOSYSTEM = "1";
process.env.GIT_CONFIG_COUNT = "0";
const cli = fileURLToPath(new URL("./bin/testigo.mjs", import.meta.url));
const root = path.join(sandbox, "project with spaces ñ");
const out = path.join(sandbox, "review output");
fs.mkdirSync(root);
fs.writeFileSync(process.env.GIT_CONFIG_GLOBAL, "[user]\n email = default-owner@example.test\n");

function run(args, ok = true) {
  const result = spawnSync(process.execPath, [cli, "export", "--root", root, "--out", out, ...args], {
    env: process.env, encoding: "utf8", maxBuffer: 8 * 1024 * 1024,
  });
  assert.ifError(result.error);
  if (ok) assert.equal(result.status, 0, result.stderr);
  else assert.notEqual(result.status, 0, "command must refuse conflicting or invalid input");
  return result;
}

function review(args = []) {
  const result = run(args);
  const file = result.stdout.match(/^pre-sign review saved: (.+)$/m)?.[1];
  assert.ok(file, result.stdout);
  const bytes = fs.readFileSync(file);
  // The full-view command must output every byte, with no clipping or wrapper.
  assert.equal(run(["--review", file]).stdout, bytes.toString("utf8"));
  assert.match(result.stdout, /summary is not the review/);
  return { file, bytes, statement: JSON.parse(bytes) };
}

function sign(saved, args = []) {
  const result = run(["--review", saved.file, "--yes", ...args]);
  const file = result.stdout.match(/^packet:   (.+)$/m)?.[1];
  const packet = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(Buffer.from(packet.envelope.payload, "base64"), saved.bytes, "signed payload is byte-for-byte the inspected review");
  for (const verify of [verifyPacket, verifyIndependent]) {
    const verdict = verify(packet);
    assert.ok(verdict.valid, JSON.stringify(verdict));
  }
  return packet;
}

try {
  const sessionId = "session-metadata-" + "x".repeat(140);
  const add = (kind, payload, caseId = "case:review") => append(root, { caseId, sessionId, kind, actor: "human", payload });
  const model = add("session_start", { model: "resolved-model-from-outside-range" }, "before-case");
  const longText = "begin\n" + "readable text ñ ".repeat(150) + "PRIVATE_PROMPT_TAIL";
  const prompt = add("prompt", { prompt: longText, context: [{ uri: "private/CLAUDE.md", sha256: "a".repeat(64) }] });
  add("tool_result", { output: "OTHER_CASE_MUST_NOT_APPEAR" }, "other-case");
  const tool = add("tool_call", { tool: "Bash", input: "command " + "x".repeat(250) + " PRIVATE_TOOL_TAIL sk-verysecretverysecretversecret1" });
  add("turn_end", {});
  const original = readLedger(root).lines;
  assert.ok(original[prompt.seq].indexOf("PRIVATE_PROMPT_TAIL") > 100, "reproduces content beyond old review excerpt");
  assert.ok(original[tool.seq].indexOf("PRIVATE_TOOL_TAIL") > 100);

  const initial = review(["--case", "case:review", "--model", "requested/provider", "--tsa", "http://127.0.0.1:1"]);
  const pred = initial.statement.predicate;
  assert.ok(!fs.existsSync(keyFile()), "review creates no signing key");
  assert.ok(!fs.readdirSync(out).some((f) => f.endsWith(".proofpack.json")), "review writes no signed packet");
  assert.ok(initial.bytes.includes("PRIVATE_PROMPT_TAIL"));
  assert.ok(initial.bytes.includes("PRIVATE_TOOL_TAIL"));
  assert.ok(initial.bytes.includes("[REDACTED:api-key]"));
  assert.ok(!initial.bytes.includes("sk-verysecret"));
  assert.ok(!initial.bytes.includes("OTHER_CASE_MUST_NOT_APPEAR"));
  assert.equal(pred.owner, "default-owner@example.test");
  assert.deepEqual(pred.provider.languageModels, [{ inferenceProvider: "requested/provider" }, { resolved: "resolved-model-from-outside-range" }]);
  assert.equal(pred.contextArtifacts[0].uri, "private/CLAUDE.md");
  assert.deepEqual(pred.range, { fromSeq: 1, toSeq: 4, prevHashBefore: JSON.parse(original[0]).hash });
  assert.equal(pred.ledgerHead.hash, JSON.parse(original.at(-1)).hash);
  assert.equal(pred.project, path.basename(root));
  assert.equal(pred.generator, "testigo-cli/0.2.0");
  assert.equal(pred.startTimestamp, new Date(prompt.ts).toISOString());
  assert.equal(pred.endTimestamp, new Date(JSON.parse(original.at(-1)).ts).toISOString());
  assert.equal(pred.events[0].line, original[prompt.seq], "unredacted raw lines preserved exactly");
  assert.deepEqual(Object.keys(pred.events[1].stub), ["seq", "prevHash", "hash", "kind"]);
  if (process.platform !== "win32") assert.equal(fs.statSync(initial.file).mode & 0o777, 0o600);
  const all = review();
  assert.equal(all.statement.predicate.caseId, null);
  assert.equal(all.statement.predicate.events.length, original.length);
  assert.ok(all.bytes.includes("OTHER_CASE_MUST_NOT_APPEAR"), "full-ledger review exposes all cases for inspection");

  // Requested redactions must actually be applied BEFORE review, including
  // derived metadata, and auto + manual on one event counts only once.
  const final = review(["--case", "case:review", "--redact", `${prompt.seq},${tool.seq},${model.seq}`, "--owner", "explicit-owner@example.test", "--model", "chosen/model"]);
  assert.notEqual(final.file, initial.file);
  assert.deepEqual(fs.readFileSync(initial.file), initial.bytes, "new review does not replace the previous snapshot");
  const finalPred = final.statement.predicate;
  assert.equal(finalPred.redactionCount, 2);
  assert.equal(finalPred.contextArtifacts, undefined);
  assert.deepEqual(finalPred.provider.languageModels, [{ inferenceProvider: "chosen/model" }]);
  assert.equal(finalPred.owner, "explicit-owner@example.test");
  for (const absent of ["PRIVATE_PROMPT_TAIL", "PRIVATE_TOOL_TAIL", "sk-verysecret", "private/CLAUDE.md", "resolved-model-from-outside-range"]) {
    assert.ok(!final.bytes.includes(absent), `${absent} removed from final review`);
  }
  for (const event of finalPred.events.filter((e) => e.line && e.redacted)) {
    const value = JSON.parse(event.line);
    assert.deepEqual(value.payload, { redacted: "manual" });
    assert.equal(value.sessionId, sessionId, "manual redaction leaves metadata visible");
    assert.equal(value.hash, JSON.parse(original[value.seq]).hash);
  }

  for (const conflict of ["--case", "--owner", "--model", "--redact"]) {
    assert.match(run(["--review", final.file, conflict, "changed", "--yes"], false).stderr, /generate a new review/);
  }
  run(["--review"], false);
  assert.ok(!fs.existsSync(keyFile()), "conflicting options do not sign");

  // Capture and defaults can change while the human reviews. Neither may
  // change signed bytes, including exportedAtMs, ledgerHead or process context.
  add("prompt", { prompt: "UNREVIEWED_NEW_EVENT" });
  add("model_switch", { to: "UNREVIEWED_NEW_MODEL" });
  fs.writeFileSync(process.env.GIT_CONFIG_GLOBAL, "[user]\n email = changed-owner@example.test\n");
  sign(initial);
  sign(final);
  sign(all);
  assert.ok(fs.existsSync(path.join(out, "testigo-verifier.html")), "standalone verifier still ships");

  // Direct --yes remains supported and uses the same redaction path.
  run(["--case", "case:review", "--redact", String(tool.seq), "--yes"]);
  const direct = JSON.parse(fs.readFileSync(path.join(out, "case-review.proofpack.json")));
  assert.ok(verifyIndependent(direct).valid);
  assert.ok(Buffer.from(direct.envelope.payload, "base64").includes("UNREVIEWED_NEW_EVENT"));

  // Auto-redaction also applies to model metadata derived outside the case.
  const secretModel = add("model_switch", { to: "sk-secretmodelsecretmodelsecretmodel" }, "after-case");
  const automatic = prepareStatement(root, { caseId: "case:review" });
  assert.ok(!JSON.stringify(automatic).includes("sk-secretmodel"));
  assert.ok(automatic.predicate.provider.languageModels.some((m) => m.resolved === "[REDACTED:api-key]"));
  const manual = prepareStatement(root, { caseId: "case:review", redactSeqs: [secretModel.seq] });
  assert.ok(!manual.predicate.provider.languageModels.some((m) => m.resolved === "[REDACTED:api-key]"));

  const badFile = path.join(sandbox, "invalid-review.json");
  const bad = structuredClone(final.statement);
  bad.predicate.redactionCount = 99;
  fs.writeFileSync(badFile, JSON.stringify(bad));
  assert.match(run(["--review", badFile, "--yes"], false).stderr, /invalid review statement \(redactionCount\)/);

  // Preparing a new review still refuses a corrupt source ledger. Signing
  // a saved review depends only on that already-reviewed snapshot.
  fs.writeFileSync(ledgerPath(root), fs.readFileSync(ledgerPath(root), "utf8").replace("PRIVATE_PROMPT_TAIL", "TAMPERED"));
  assert.match(run([], false).stderr, /ledger chain broken/);
  sign(final);
  console.log("testigo-cli: review regression assertions pass (complete content, metadata, redactions, frozen bytes, CLI workflow, verify ×2)");
} finally {
  fs.rmSync(sandbox, { recursive: true, force: true });
}
