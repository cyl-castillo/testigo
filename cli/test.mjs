#!/usr/bin/env node
// End-to-end test for testigo-cli, run inside a throwaway XDG sandbox:
//
//   1. Feed a realistic Claude Code hook sequence (prompt → tool calls →
//      results → stop, two concurrent sessions, a secret in a tool input).
//   2. Case-link one session; verify the chain; check torn-tail healing
//      and concurrent-append integrity.
//   3. Export the case with a manual redaction; verify the packet with the
//      CLI's own verifier AND with the conformance suite's independent one.
//   4. Run the CLI verifier over every conformance vector and require the
//      manifest verdicts — the CLI is an implementation; the suite is its oracle.
//
// No network: the timestamp path is covered by the conformance vectors.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HERE = path.dirname(new URL(import.meta.url).pathname);
const SANDBOX = fs.mkdtempSync(path.join(os.tmpdir(), "testigo-cli-test-"));
process.env.XDG_DATA_HOME = path.join(SANDBOX, "data");
process.env.XDG_CONFIG_HOME = path.join(SANDBOX, "config");

// Import AFTER the env is set — lib paths read XDG at call time, but stay safe.
const { handleHook } = await import("./lib/hook.mjs");
const { append, ledgerPath, readLedger, verifyChain } = await import("./lib/ledger.mjs");
const { exportPacket, preview } = await import("./lib/export.mjs");
const { verifyPacket } = await import("./lib/verify.mjs");
const conformance = await import("../conformance/verify.mjs");

const ROOT = path.join(SANDBOX, "proj");
fs.mkdirSync(ROOT, { recursive: true });
const S1 = "session-aaaa";
const S2 = "session-bbbb";
const hook = (o) => handleHook({ cwd: ROOT, ...o });

// ---- 1. capture ------------------------------------------------------------

hook({ hook_event_name: "UserPromptSubmit", session_id: S1, prompt: "deploy the release" });
hook({ hook_event_name: "PreToolUse", session_id: S1, tool_name: "Bash", tool_input: { command: "git push" } });
// Interleaved second session (concurrent turn) with a token-shaped secret.
hook({ hook_event_name: "UserPromptSubmit", session_id: S2, prompt: "rotate the key sk-verysecretverysecretversecret1" });
hook({ hook_event_name: "PostToolUse", session_id: S1, tool_name: "Bash", tool_response: "Everything up-to-date" });
hook({ hook_event_name: "Stop", session_id: S1 });
hook({ hook_event_name: "Stop", session_id: S2 });
// Unknown hook events must be ignored, never recorded or thrown.
hook({ hook_event_name: "SomethingNew", session_id: S1 });

let { parsed } = readLedger(ROOT);
assert.equal(parsed.length, 6, "6 events captured");
assert.deepEqual(
  parsed.map((e) => e.kind),
  ["prompt", "tool_call", "prompt", "tool_result", "turn_end", "turn_end"],
);
assert.equal(parsed[0].caseId, `term:${S1}`, "case falls back to term:<session>");
assert.equal(parsed[1].turnId, parsed[0].turnId, "tool_call binds to the open turn");
assert.equal(parsed[3].turnId, parsed[0].turnId, "interleaved sessions keep their own turns");
assert.notEqual(parsed[2].turnId, parsed[0].turnId);

// ---- 2. case link + chain + torn tail ---------------------------------------

append(ROOT, { caseId: "jira:CONF-9", kind: "case_link", termId: S1, actor: "system", payload: {} });
hook({ hook_event_name: "UserPromptSubmit", session_id: S1, prompt: "second turn, now linked" });
// An S2 prompt lands INSIDE the case's range — it must export as a stub.
hook({ hook_event_name: "UserPromptSubmit", session_id: S2, prompt: "interleaved other-case work" });
hook({ hook_event_name: "Stop", session_id: S1 });
hook({ hook_event_name: "Stop", session_id: S2 });
({ parsed } = readLedger(ROOT));
const linked = parsed.filter((e) => e.caseId === "jira:CONF-9");
assert.deepEqual(linked.map((e) => e.kind), ["case_link", "prompt", "turn_end"], "post-link S1 events carry the case");
assert.ok(verifyChain(ROOT).ok, "chain verifies");

// Torn tail: simulate a crash mid-append, then witness again — healed.
fs.appendFileSync(ledgerPath(ROOT), '{"seq":99,"ts":1,"caseId"');
assert.ok(verifyChain(ROOT).tornTail, "torn tail detected");
hook({ hook_event_name: "UserPromptSubmit", session_id: S2, prompt: "after the crash" });
hook({ hook_event_name: "Stop", session_id: S2 });
const healed = verifyChain(ROOT);
assert.ok(healed.ok && !healed.tornTail, "torn tail healed by the next append");
({ parsed } = readLedger(ROOT));

// ---- 3. export: auto + manual redaction, stubs, both verifiers agree --------

// The S2 prompt (with the secret) is out-of-case → stub. Manually redact the
// linked prompt too.
const pv = preview(ROOT, "jira:CONF-9");
assert.ok(pv.entries.some((e) => e.stub), "out-of-case events preview as stubs");
const linkedPromptSeq = parsed.find((e) => e.caseId === "jira:CONF-9" && e.kind === "prompt").seq;
const sum = await exportPacket(ROOT, {
  caseId: "jira:CONF-9",
  outDir: path.join(SANDBOX, "out"),
  redactSeqs: [linkedPromptSeq],
});
const packet = JSON.parse(fs.readFileSync(sum.path, "utf8"));

for (const [name, verify] of [["cli", verifyPacket], ["conformance", conformance.verifyPacket]]) {
  const r = verify(packet);
  assert.ok(r.valid, `${name} verifier: packet valid`);
  assert.equal(r.counts.stubs, sum.stubs, `${name}: stub count agrees`);
  assert.ok(r.counts.redacted >= 1, `${name}: redaction visible`);
}

// The secret never appears anywhere in the packet (it lives in a stub).
assert.ok(!fs.readFileSync(sum.path, "utf8").includes("sk-verysecret"), "secret not in packet");
// Auto-redaction fires when the secret IS in-case: full-ledger export.
const sumAll = await exportPacket(ROOT, { caseId: null, outDir: path.join(SANDBOX, "out") });
const allText = fs.readFileSync(sumAll.path, "utf8");
assert.ok(!allText.includes("sk-verysecret"), "secret auto-redacted in full export");
assert.ok(Buffer.from(JSON.parse(allText).envelope.payload, "base64").includes("[REDACTED:api-key]"));
assert.ok(verifyPacket(JSON.parse(allText)).valid, "redacted full export still verifies");

// ---- 4. the conformance suite is the CLI verifier's oracle ------------------

const vecDir = path.join(HERE, "..", "conformance", "vectors");
const manifest = JSON.parse(fs.readFileSync(path.join(vecDir, "manifest.json"), "utf8"));
for (const v of manifest.vectors) {
  const got = verifyPacket(JSON.parse(fs.readFileSync(path.join(vecDir, v.file), "utf8")));
  assert.equal(got.valid, v.expect.valid, `${v.file}: valid`);
  if (!v.expect.valid) assert.equal(got.firstFailure, v.expect.firstFailure, `${v.file}: firstFailure`);
  if (v.expect.counts) assert.deepEqual(got.counts, { ...got.counts, ...v.expect.counts }, `${v.file}: counts`);
  if (v.expect.timestamp) assert.equal(got.timestamp, v.expect.timestamp, `${v.file}: timestamp`);
}

fs.rmSync(SANDBOX, { recursive: true, force: true });
console.log("testigo-cli: all e2e assertions pass (capture, link, heal, export, redact, verify ×2, conformance ×" + manifest.vectors.length + ")");
