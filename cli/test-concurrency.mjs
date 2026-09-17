import assert from "node:assert/strict";
import { fork } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { append, ledgerKey, ledgerPath, readLedger, readState, verifyChain } from "./lib/ledger.mjs";
import { handleHook } from "./lib/hook.mjs";

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "testigo-concurrency-"));
process.env.XDG_DATA_HOME = path.join(sandbox, "data");
const root = path.join(sandbox, "project");
fs.mkdirSync(root);
const sessions = Array.from({ length: 24 }, (_, i) => `session-${i}`);

async function batch(inputs, { env = {}, afterStart, diagnostics = false, expectedCode = 0 } = {}) {
  const children = inputs.map((input) => {
    const child = fork(new URL("./test-concurrency-worker.mjs", import.meta.url), input.args ?? ["hook"], {
      silent: true, env: { ...process.env, TESTIGO_DEBUG: "1", ...env },
    });
    let stderr = "";
    child.stderr.on("data", (data) => { stderr += data; });
    child.stdout.resume();
    const ready = new Promise((resolve, reject) => {
      child.once("message", resolve);
      child.once("error", reject);
      child.once("exit", () => reject(new Error(`worker exited before ready: ${stderr}`)));
    });
    const done = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) => resolve({ code, stderr }));
    });
    child.stdin.end(JSON.stringify({ cwd: root, ...input }));
    // Bound a broken regression/worker so CI cannot hang indefinitely.
    const timer = setTimeout(() => child.kill(), 20_000);
    child.once("exit", () => clearTimeout(timer));
    return { child, ready, done };
  });
  try {
    await Promise.all(children.map((c) => c.ready));
    for (const c of children) c.child.send("go");
    if (afterStart) await afterStart(children);
    const results = await Promise.all(children.map((c) => c.done));
    assert.ok(results.every((r) => r.code === expectedCode), JSON.stringify(results));
    if (!diagnostics) assert.ok(results.every((r) => r.stderr === ""), JSON.stringify(results));
    return results;
  } finally {
    for (const c of children) if (c.child.exitCode === null) c.child.kill();
    await Promise.allSettled(children.map((c) => c.done));
  }
}

async function waitFor(file) {
  const deadline = Date.now() + 10_000;
  while (!fs.existsSync(file)) {
    assert.ok(Date.now() < deadline, `timed out waiting for ${file}`);
    await delay(10);
  }
}

const hook = (session_id, hook_event_name, extra = {}) => ({ session_id, hook_event_name, ...extra });
const direct = (input) => handleHook({ cwd: root, ...input });
const link = (session, caseId) => ({ args: ["link", caseId, "--term", session, "--root", root] });

// Independently check binding against ledger order, not merely chain hashes.
function checkBindings() {
  const turns = new Map();
  const cases = new Map();
  for (const event of readLedger(root).parsed) {
    if (event.kind === "case_link") {
      cases.set(event.termId, event.caseId);
      continue;
    }
    assert.equal(event.caseId, cases.get(event.termId) ?? `term:${event.termId}`, `case at seq ${event.seq}`);
    if (event.kind === "prompt") {
      assert.ok(event.turnId);
      turns.set(event.sessionId, event.turnId);
    } else {
      assert.equal(event.turnId, turns.get(event.sessionId), `turn at seq ${event.seq}`);
      if (event.kind === "turn_end") turns.delete(event.sessionId);
    }
  }
  assert.deepEqual(new Map(Object.entries(readState(root).sessions).map(([s, value]) => [s, value.turnId])), turns);
  assert.ok(verifyChain(root).ok);
}

try {
  const results = await batch(sessions.map((s) => hook(s, "UserPromptSubmit", { prompt: `prompt for ${s}` })));
  const prompts = readLedger(root).parsed;
  const state = readState(root);
  console.log(`24 concurrent prompts: ${prompts.length} recorded, ${Object.keys(state.sessions).length} active sessions; chain valid: ${verifyChain(root).ok}`);
  assert.equal(prompts.length, sessions.length, `all prompts preserved; hook diagnostics: ${JSON.stringify(results)}`);
  assert.equal(Object.keys(state.sessions).length, sessions.length, "all session state preserved");
  assert.equal(new Set(prompts.map((p) => p.turnId)).size, sessions.length);
  assert.deepEqual(new Set(prompts.map((p) => p.payload.prompt)), new Set(sessions.map((s) => `prompt for ${s}`)));
  await batch(sessions.map((s) => hook(s, "PreToolUse", { tool_name: s, tool_input: { command: "echo ok" } })));
  await batch(sessions.flatMap((s) => [
    hook(s, "PostToolUse", { tool_name: s, tool_response: "ok" }),
    hook(s, "PostModelSwitch", { from_model: "a", to_model: "b" }),
  ]));
  // Session stops and new prompts compete with links in the same project.
  await batch(sessions.flatMap((s, i) => [
    hook(s, i < 12 ? "Stop" : "UserPromptSubmit", { prompt: `next ${s}` }), link(s, `case:${s}`),
  ]));
  await batch(sessions.map((s) => hook(s, "PreToolUse", { tool_name: `later ${s}` })));
  await batch(sessions.map((s) => hook(s, "Stop")));
  assert.equal(readLedger(root).parsed.length, 192, "every submitted hook and link was captured");
  assert.equal(Object.keys(readState(root).sessions).length, 0);
  checkBindings();

  // Truly simultaneous events within one session are ordered by lock acquisition.
  await batch(Array.from({ length: 8 }, (_, i) => [
    hook("shared", "UserPromptSubmit", { prompt: `shared ${i}` }),
    hook("shared", "PreToolUse", { tool_name: `shared ${i}` }),
    hook("shared", "Stop"), link("shared", `shared-case:${i}`),
  ]).flat());
  assert.equal(readLedger(root).parsed.length, 224);
  checkBindings();

  // Deterministic boundary test: pause a tool just before its lock attempt.
  // A new prompt/link completes while it waits. Binding before locking fails.
  direct(hook("boundary", "UserPromptSubmit", { prompt: "before" }));
  const barrier = path.join(sandbox, "before-lock");
  await batch([hook("boundary", "PreToolUse")], {
    env: { TESTIGO_TEST_BEFORE_LOCK: barrier },
    afterStart: async () => {
      await waitFor(`${barrier}.ready`);
      direct(hook("boundary", "UserPromptSubmit", { prompt: "after" }));
      append(root, { caseId: "boundary-case", kind: "case_link", termId: "boundary", actor: "system", payload: {} });
      fs.writeFileSync(barrier, "");
    },
  });
  checkBindings();

  // Legacy cache contents (including phantom turns) and an unusable cache
  // directory cannot override the ledger or prevent an event from recording.
  const legacy = path.join(process.env.XDG_DATA_HOME, "testigo", "state");
  fs.mkdirSync(legacy, { recursive: true });
  fs.writeFileSync(path.join(legacy, `${ledgerKey(root)}.json`), JSON.stringify({
    sessions: { boundary: { turnId: "phantom", lastTs: Date.now() } }, cases: { boundary: "wrong-case" },
  }));
  await batch([hook("boundary", "PreToolUse")]);
  fs.rmSync(legacy, { recursive: true });
  fs.writeFileSync(legacy, "not a directory");
  await batch([hook("boundary", "UserPromptSubmit", { prompt: "cache unavailable" })]);
  checkBindings();

  // Append failure exits 0 and cannot open a phantom turn or close a real one.
  for (const name of ["UserPromptSubmit", "Stop"]) {
    const before = fs.readFileSync(ledgerPath(root));
    const failed = await batch([hook("boundary", name, { prompt: "cannot record" })], {
      env: { TESTIGO_TEST_FAIL_APPEND: "1" }, diagnostics: true,
    });
    assert.match(failed[0].stderr, /injected append failure/);
    assert.deepEqual(fs.readFileSync(ledgerPath(root)), before);
    await batch([hook("boundary", "PreToolUse")]);
    checkBindings();
  }

  // A live lock remains exclusive even with an artificially old mtime.
  const lock = `${ledgerPath(root)}.lock`;
  fs.mkdirSync(lock);
  const owner = path.join(lock, `${process.pid}-00000000-0000-0000-0000-000000000000`);
  fs.writeFileSync(owner, "");
  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(lock, old, old);
  try {
    const before = fs.readFileSync(ledgerPath(root));
    const blocked = await batch([hook("boundary", "Stop")], { diagnostics: true });
    assert.match(blocked[0].stderr, /ledger lock stuck/);
    assert.deepEqual(fs.readFileSync(ledgerPath(root)), before);
    assert.ok(fs.existsSync(owner));
  } finally {
    fs.unlinkSync(owner);
    fs.rmdirSync(lock);
  }

  // Kill an actual lock holder; concurrent successors must reclaim only its
  // unique ownership marker, without deleting a successor's lock.
  const holderReady = path.join(process.env.XDG_DATA_HOME, "holder-ready");
  const holder = fork(new URL("./test-concurrency-worker.mjs", import.meta.url), ["hold-lock", ledgerPath(root)], { silent: true });
  const exited = new Promise((resolve) => holder.once("exit", resolve));
  holder.once("message", () => holder.send("go"));
  try {
    await waitFor(holderReady);
  } finally {
    holder.kill();
    await exited;
  }
  await batch(sessions.map((s) => hook(s, "UserPromptSubmit", { prompt: `after crash ${s}` })));
  assert.equal(readLedger(root).parsed.length, 256, "all successful invocations preserved, failed appends absent");
  assert.ok(!fs.existsSync(lock), "successors release their locks");
  checkBindings();

  // Stop's transcript commitment and closure stay together under contention.
  const transcript = path.join(sandbox, "transcript.jsonl");
  fs.writeFileSync(transcript, '{"message":"transcript evidence"}\n');
  await batch(sessions.map((s) => hook(s, "Stop", { transcript_path: transcript })));
  const withEvidence = readLedger(root).parsed;
  assert.equal(withEvidence.length, 304);
  for (let i = 256; i < withEvidence.length; i += 2) {
    const [evidence, end] = withEvidence.slice(i, i + 2);
    assert.equal(evidence.kind, "external_evidence");
    assert.equal(end.kind, "turn_end");
    assert.equal(evidence.turnId, end.turnId);
    assert.equal(evidence.sessionId, end.sessionId);
    assert.equal(evidence.caseId, end.caseId);
  }
  checkBindings();

  // Auto-selection for link shares the same boundary, including the error
  // path: reporting an empty session list must not exit while holding a lock.
  const emptyRoot = path.join(sandbox, "empty-project");
  const autoLink = { args: ["link", "auto-case", "--root", emptyRoot] };
  const noSession = await batch([autoLink], { expectedCode: 1, diagnostics: true });
  assert.match(noSession[0].stderr, /no active session found/);
  assert.ok(!fs.existsSync(`${ledgerPath(emptyRoot)}.lock`));
  await batch([hook("auto-session", "UserPromptSubmit", { cwd: emptyRoot, prompt: "auto link" })]);
  await batch([autoLink], { env: process.platform === "win32" ? { TESTIGO_TEST_LOCK_EPERM: "1" } : {} });
  assert.equal(readLedger(emptyRoot).parsed.at(-1).termId, "auto-session");
  assert.equal(readState(emptyRoot).cases["auto-session"], "auto-case");
  console.log("concurrency: all assertions pass (24 sessions, shared session, links, deterministic binding boundary, legacy cache, append failures, lock timeout and crashed owner)");
} finally {
  fs.rmSync(sandbox, { recursive: true, force: true });
}
