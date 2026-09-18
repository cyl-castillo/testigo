// Real subprocess regressions: execute the installed commands, not just
// their string representation. All writes stay in a throwaway directory.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { hookCommand } from "./lib/command.mjs";

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
  assert.match(cli(["init", "--root", root]), /installed 6 entries/);
  assert.deepEqual(readJSON(`${settings}.bak`), existing);
  const once = readJSON(settings);
  assert.match(cli(["init", "--root", root]), /already installed/);
  assert.deepEqual(readJSON(settings), once);
  assert.deepEqual(readJSON(`${settings}.bak`), existing, "a no-op preserves the migration backup");
  assert.deepEqual(once.permissions, existing.permissions);
  assert.equal(once.hooks.Stop.length, 2);
  const override = 'node "C:\\custom path\\hook.mjs" --literal \'quoted\'';
  for (let i = 0; i < 2; i++) cli(["init", "--root", root, "--shell", "powershell", "--command", override]);
  const hooks = readJSON(settings).hooks.Stop;
  assert.equal(hooks.length, 2, "an explicit command override replaces this CLI's generated hooks");
  assert.deepEqual(hooks.at(-1).hooks[0], { type: "command", command: override, shell: "powershell" });
  const rejected = spawnSync(process.execPath, [CLI, "init", "--print", "--shell", "cmd"], { env, encoding: "utf8" });
  assert.equal(rejected.status, 1);
  assert.match(rejected.stderr, /--shell must be bash or powershell/);
});

function seedSettings(root, hooks) {
  const settings = path.join(root, ".claude/settings.json");
  fs.mkdirSync(path.dirname(settings), { recursive: true });
  const original = { permissions: { allow: [] }, hooks };
  fs.writeFileSync(settings, JSON.stringify(original));
  return { settings, original };
}

const prePRCommand = `node ${path.resolve(pathToFileURL(CLI).pathname)} hook`;
for (const [shell, executable, flags] of [
  ["bash", bash, ["-c"]],
  ["powershell", powershell, ["-NoProfile", "-NonInteractive", "-Command"]],
]) {
  test(`pre-PR settings migrate to ${shell} with one capture per event`,
    { skip: !executable && `${shell} is not available on this host` }, () => {
      const root = path.join(TEMP, `upgrade ${shell}`);
      // Exactly the old settings shape and URL-path construction, including
      // percent encoding and the broken Windows drive prefix.
      const { settings, original } = seedSettings(root, Object.fromEntries(events.map((event) =>
        [event, [{ hooks: [{ type: "command", command: prePRCommand }] }]])));
      const options = ["init", "--root", root, "--shell", shell];
      assert.match(cli(options), /replaced 6 legacy entries/);
      assert.deepEqual(readJSON(`${settings}.bak`), original);
      const upgraded = readJSON(settings);
      for (const event of events) {
        const handlers = upgraded.hooks[event].flatMap((group) => group.hooks);
        assert.equal(handlers.length, 1, event);
        assert.equal(handlers[0].shell, shell);
        run(executable, [...flags, handlers[0].command], {
          input: JSON.stringify({ cwd: root, hook_event_name: event, session_id: shell,
            prompt: "one migrated prompt", model: "test-model", from_model: "before", to_model: "after",
            tool_name: "Bash", tool_input: { command: "echo test" }, tool_response: "test" }),
        });
      }
      assert.match(cli(["verify", "--root", root]), /chain ok: 6 events/);
      assert.equal(cli(["log", "--root", root]).split("one migrated prompt").length - 1, 1);
      assert.match(cli(options), /already installed/);
      assert.deepEqual(readJSON(settings), upgraded);
      assert.deepEqual(readJSON(`${settings}.bak`), original);
    });
}

test("init recognizes literal quoting, script path aliases, and different Node locations", () => {
  const root = path.join(TEMP, "literal variants");
  const native = (s) => process.platform === "win32" ? s.replaceAll("\\", "/") : s;
  const doubleQuote = (s) => `"${s.replace(/[\\"$`]/g, "\\$&")}"`;
  const oldNode = path.join(TEMP, "removed node version", "node");
  const handlers = [
    { command: prePRCommand },
    { command: hookCommand(oldNode, CLI) },
    { command: `${doubleQuote(native(oldNode))} ${doubleQuote(native(CLI))} hook` },
    { command: hookCommand(oldNode + ".exe", CLI, "powershell"), shell: "powershell" },
    { command: hookCommand("nodejs", path.relative(root, CLI)) },
    { command: hookCommand("node", `${path.dirname(CLI)}/../bin/testigo.mjs`) },
  ];
  const { settings } = seedSettings(root, Object.fromEntries(events.map((event, i) =>
    [event, [{ hooks: [{ type: "command", ...handlers[i] }] }]])));
  assert.match(cli(["init", "--root", root]), /replaced 6 legacy entries/);
  const expected = JSON.parse(cli(["init", "--print"]));
  assert.deepEqual(readJSON(settings).hooks, expected.hooks);
});

test("init repairs mixed legacy/current duplicates without removing unrelated hooks or scopes", () => {
  const root = path.join(TEMP, "mixed duplicates");
  const current = JSON.parse(cli(["init", "--print"])).hooks.Stop[0].hooks[0];
  const legacy = { type: "command", command: prePRCommand, timeout: 20 };
  const unrelated = [
    { type: "command", command: "echo keep" },
    { type: "command", command: `echo '${CLI}' hook` },
    { type: "command", command: `${current.command} && echo keep` },
    { type: "command", command: `env EXTRA=1 ${current.command}` },
    { type: "command", command: 'node "$TESTIGO_SCRIPT" hook' },
    { type: "command", command: `${current.command} --extra` },
    { type: "command", command: hookCommand("node", path.join(TEMP, "other/bin/testigo.mjs")) },
    { ...current, args: ["custom-exec-form"] },
  ];
  const restricted = { matcher: "Bash", hooks: [legacy] };
  const conditional = { if: "Bash(git *)", hooks: [legacy] };
  const { settings, original } = seedSettings(root, Object.fromEntries(events.map((event) => [event, [
    { hooks: [...unrelated, legacy] }, { hooks: [current] }, { matcher: "*", hooks: [legacy] },
    restricted, conditional,
  ]])));
  assert.match(cli(["init", "--root", root]), /replaced 6 legacy entries; removed 12 duplicate entries/);
  for (const event of events) {
    assert.deepEqual(readJSON(settings).hooks[event], [
      { hooks: [...unrelated, { ...legacy, ...current }] }, restricted, conditional,
    ]);
  }
  assert.deepEqual(readJSON(`${settings}.bak`), original);
  assert.match(cli(["init", "--root", root]), /already installed/);
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
