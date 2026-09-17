// Real subprocess regressions: execute the installed commands, not just
// their string representation. All writes stay in a throwaway directory.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("../", import.meta.url));
const TEMP = fs.mkdtempSync(path.join(os.tmpdir(), "testigo-portability-"));
after(() => fs.rmSync(TEMP, { recursive: true, force: true }));
// Legal on Windows as well as POSIX; URL decoding and shell expansion are
// separate hazards. The executable (Program Files on Windows) has spaces too.
const COPY = path.join(TEMP, "checkout space é # % ' ‘curly’ ‚‛ $dollar `tick` & semi; [x] !");
for (const dir of ["cli", "conformance", "predicate", "verifier"]) {
  fs.cpSync(path.join(REPO, dir), path.join(COPY, dir), { recursive: true });
}
const CLI = path.join(COPY, "cli", "bin", "testigo.mjs");
const env = {
  ...process.env,
  XDG_DATA_HOME: path.join(TEMP, "data"),
  XDG_CONFIG_HOME: path.join(TEMP, "config"),
  GIT_CONFIG_GLOBAL: path.join(TEMP, "gitconfig"),
  GIT_CONFIG_NOSYSTEM: "1",
  TESTIGO_DEBUG: "1",
};
fs.writeFileSync(env.GIT_CONFIG_GLOBAL, "");

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: TEMP, env, encoding: "utf8", timeout: 60_000, ...options,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${executable}: ${result.stdout}\n${result.stderr}`);
  return result.stdout;
}
const cli = (args, options) => run(process.execPath, [CLI, ...args], options);
const readJSON = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const events = ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostModelSwitch", "Stop"];

const bash = process.platform === "win32"
  ? [process.env.TESTIGO_TEST_BASH, path.join(process.env.ProgramFiles ?? "C:/Program Files", "Git/bin/bash.exe"),
    path.join(process.env.LOCALAPPDATA ?? "", "Programs/Git/bin/bash.exe")].find((p) => p && fs.existsSync(p))
  : "/bin/sh";
const powershell = process.platform === "win32"
  ? path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe")
  : null;

for (const [shell, executable, flags] of [
  ["bash", bash, ["-c"]],
  ["powershell", powershell, ["-NoProfile", "-NonInteractive", "-Command"]],
]) {
  test(`generated ${shell} command captures a hook from a special-character path`,
    { skip: !executable && `${shell} is not available on this host` }, () => {
      const config = JSON.parse(cli(["init", "--print", "--shell", shell]));
      assert.deepEqual(Object.keys(config.hooks), events);
      const handler = config.hooks.UserPromptSubmit[0].hooks[0];
      assert.equal(handler.shell, shell);
      for (const event of events) assert.deepEqual(config.hooks[event][0].hooks[0], handler);
      if (shell === "bash") {
        assert.deepEqual(JSON.parse(cli(["init", "--print"])), config, "default shell is explicit Bash");
      }
      assert.equal(fs.existsSync(path.join(TEMP, ".claude/settings.json")), false, "--print does not write settings");
      const root = path.join(TEMP, `project ${shell}`);
      fs.mkdirSync(root);
      const prompt = `captured through ${shell}`;
      run(executable, [...flags, handler.command], {
        input: JSON.stringify({ cwd: root, hook_event_name: "UserPromptSubmit", session_id: shell, prompt }),
      });
      assert.match(cli(["log", "--root", root]), new RegExp(prompt));
      assert.match(cli(["verify", "--root", root]), /chain ok: 1 events/);
    });
}

test("init merges settings and remains idempotent with quoted commands", () => {
  const root = path.join(TEMP, "settings project");
  const settings = path.join(root, ".claude/settings.json");
  fs.mkdirSync(path.dirname(settings), { recursive: true });
  const existing = { permissions: { allow: [] }, hooks: { Stop: [{ hooks: [{ type: "command", command: "echo existing" }] }] } };
  fs.writeFileSync(settings, JSON.stringify(existing));
  cli(["init", "--root", root]);
  assert.deepEqual(readJSON(`${settings}.bak`), existing);
  const once = readJSON(settings);
  cli(["init", "--root", root]);
  assert.deepEqual(readJSON(settings), once);
  assert.deepEqual(once.permissions, existing.permissions);
  assert.equal(once.hooks.Stop.length, 2);
  const override = 'node "C:\\custom path\\hook.mjs" --literal \'quoted\'';
  for (let i = 0; i < 2; i++) cli(["init", "--root", root, "--shell", "powershell", "--command", override]);
  const hooks = readJSON(settings).hooks.Stop;
  assert.equal(hooks.length, 3);
  assert.deepEqual(hooks.at(-1).hooks[0], { type: "command", command: override, shell: "powershell" });
  const rejected = spawnSync(process.execPath, [CLI, "init", "--print", "--shell", "cmd"], { env, encoding: "utf8" });
  assert.equal(rejected.status, 1);
  assert.match(rejected.stderr, /--shell must be bash or powershell/);
});

test("--user uses the platform home rather than the working directory", () => {
  const userHome = path.join(TEMP, "user home é");
  const project = path.join(TEMP, "user init project");
  fs.mkdirSync(project);
  const userEnv = { ...env, USERPROFILE: userHome, HOME: userHome };
  if (process.platform === "win32") delete userEnv.HOME;
  const options = { env: userEnv, cwd: project };
  cli(["init", "--user"], options);
  const settings = path.join(userHome, ".claude/settings.json");
  const once = readJSON(settings);
  // A Git Bash HOME override must not displace native Windows USERPROFILE.
  if (process.platform === "win32") userEnv.HOME = path.join(TEMP, "wrong home");
  cli(["init", "--user"], options);
  assert.deepEqual(readJSON(settings), once);
  assert.equal(fs.existsSync(path.join(project, ".claude/settings.json")), false);
  assert.equal(fs.existsSync(path.join(TEMP, "wrong home/.claude/settings.json")), false);
});

test("official test and vector entrypoints work from a URL-encoded checkout path", () => {
  assert.match(run(process.execPath, [path.join(COPY, "cli/test.mjs")]), /all e2e assertions pass/);
  const output = run(process.execPath, [path.join(COPY, "conformance/verify.mjs")]);
  assert.match(output, /all \d+ conformance vectors pass/);
  assert.match(output, /all \d+ session-chain vectors pass/);
  // Regenerate only the disposable copy, including reading the token fixture.
  const vectors = path.join(COPY, "conformance/vectors");
  // Git may check JSON files out with CRLF on Windows; signed payload bytes
  // remain base64 and must still match exactly.
  const readVector = (name) => fs.readFileSync(path.join(vectors, name), "utf8").replaceAll("\r\n", "\n");
  const before = new Map(fs.readdirSync(vectors).map((name) => [name, readVector(name)]));
  run(process.execPath, [path.join(COPY, "conformance/generate.mjs")]);
  for (const [name, bytes] of before) assert.equal(readVector(name), bytes, name);
});

test("export finds a packaged verifier and retains the hosted fallback when absent", () => {
  const packaged = path.join(TEMP, "packaged cli # é");
  fs.cpSync(path.join(COPY, "cli"), packaged, { recursive: true });
  const bin = path.join(packaged, "bin/testigo.mjs");
  const root = path.join(TEMP, "export project");
  fs.mkdirSync(root);
  run(process.execPath, [bin, "hook"], { input: JSON.stringify({ cwd: root, hook_event_name: "UserPromptSubmit", session_id: "export", prompt: "export test" }) });
  const out = path.join(TEMP, "export output # é");
  const args = [bin, "export", "--yes", "--root", root, "--out", out, "--owner", "test"];
  assert.match(run(process.execPath, args), /verifier: https:\/\/.*testigo-verifier.html/);
  assert.equal(fs.existsSync(path.join(out, "testigo-verifier.html")), false);
  fs.mkdirSync(path.join(packaged, "verifier"));
  const source = path.join(REPO, "verifier/testigo-verifier.html");
  fs.copyFileSync(source, path.join(packaged, "verifier/testigo-verifier.html"));
  run(process.execPath, args);
  assert.deepEqual(fs.readFileSync(path.join(out, "testigo-verifier.html")), fs.readFileSync(source));
});
