#!/usr/bin/env node
// testigo — witness CLI: ambient intent-to-proof capture from Claude Code
// hooks, chain verification, and signed proof-packet export. Witness, not
// gatekeeper: it records; it never orchestrates or blocks.

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { append, caseFor, ledgerPath, readLedger, readState, verifyChain, writeState } from "../lib/ledger.mjs";
import { handleHook, hooksConfig } from "../lib/hook.mjs";
import { exportPacket, keyInfo, preview } from "../lib/export.mjs";
import { verifyPacket } from "../lib/verify.mjs";

const HELP = `testigo — witness CLI for the Testigo protocol (spec: github.com/cyl-castillo/testigo)

usage: testigo <command> [options]

  init [--user] [--print] [--command CMD]
        Install the capture hooks into Claude Code settings
        (./.claude/settings.json; --user targets ~/.claude/settings.json;
        --print only shows the JSON). Existing settings are merged, a .bak
        is written first.
  hook  Hook entrypoint (reads the Claude Code hook JSON from stdin).
        Wired by init; never breaks a session — errors exit 0
        (TESTIGO_DEBUG=1 to see them).
  log [--case ID] [-n N] [--root DIR]
        Show recent ledger events (newest last).
  link <caseId> [--term ID] [--root DIR]
        Bind a session to a case (e.g. jira:FIXY-12, github:org/repo#5).
        Defaults to the most recently active session.
  verify [--root DIR]
        Walk the project ledger's hash chain.
  export [--case ID] [--out DIR] [--redact s1,s2] [--tsa URL] [--yes] [--root DIR]
        Review-then-sign a proof packet. Without --yes it prints the
        pre-sign review (everything the packet would contain) and stops —
        nothing leaves unreviewed. --tsa requests an RFC 3161 timestamp
        (e.g. https://freetsa.org/tsr; sends the TSA a signature hash only).
  verify-packet <file>
        Verify any proof packet per spec §2.4 (offline).
  key   Show this machine's signing key id + public key (created on first use).

Captured via hooks: prompts, tool calls, tool results, turn ends — bound by
the engine's session id. NOT captured: human approval decisions (Claude Code
hooks don't expose the permission dialog); producers in the permission path,
like agent-console, add those.`;

const args = process.argv.slice(2);
const cmd = args[0];

function flag(name) {
  const i = args.indexOf(name);
  return i !== -1;
}
function opt(name, dflt = undefined) {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] !== undefined ? args[i + 1] : dflt;
}
const ROOT = path.resolve(opt("--root", process.cwd()));

function die(msg) {
  console.error(`testigo: ${msg}`);
  process.exit(1);
}

switch (cmd) {
  case "hook": {
    let raw = "";
    process.stdin.setEncoding("utf8");
    for await (const chunk of process.stdin) raw += chunk;
    try {
      handleHook(JSON.parse(raw));
    } catch (e) {
      if (process.env.TESTIGO_DEBUG) console.error(`testigo hook: ${e.message}`);
      // exit 0 regardless: witnessing must never break the session
    }
    break;
  }

  case "init": {
    const self = path.resolve(new URL(import.meta.url).pathname);
    const command = opt("--command", `node ${self} hook`);
    const config = { hooks: hooksConfig(command) };
    if (flag("--print")) {
      console.log(JSON.stringify(config, null, 2));
      break;
    }
    const target = flag("--user")
      ? path.join(process.env.HOME ?? "", ".claude", "settings.json")
      : path.join(ROOT, ".claude", "settings.json");
    let existing = {};
    if (fs.existsSync(target)) {
      existing = JSON.parse(fs.readFileSync(target, "utf8"));
      fs.copyFileSync(target, `${target}.bak`);
    }
    existing.hooks ??= {};
    for (const [event, matchers] of Object.entries(config.hooks)) {
      existing.hooks[event] ??= [];
      const already = JSON.stringify(existing.hooks[event]).includes(command);
      if (!already) existing.hooks[event].push(...matchers);
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(existing, null, 2) + "\n");
    console.log(`hooks installed in ${target}${fs.existsSync(`${target}.bak`) ? ` (previous saved as .bak)` : ""}`);
    console.log(`ledger will be written to ${ledgerPath(ROOT)}`);
    console.log(`note: running Claude Code sessions pick hooks up on restart.`);
    break;
  }

  case "log": {
    const { parsed } = readLedger(ROOT);
    const caseId = opt("--case");
    const n = parseInt(opt("-n", "20"), 10);
    const rows = parsed.filter((e) => !caseId || e.caseId === caseId).slice(-n);
    if (!rows.length) {
      console.log("no events recorded yet");
      break;
    }
    for (const e of rows) {
      const p = e.payload ?? {};
      const detail =
        e.kind === "prompt"
          ? (p.prompt ?? "").slice(0, 80)
          : e.kind === "tool_call" || e.kind === "tool_result"
            ? `tool=${p.tool}`
            : e.kind === "case_link"
              ? e.caseId
              : "";
      console.log(
        `${String(e.seq).padStart(4)}  ${new Date(e.ts).toISOString()}  ${e.caseId.padEnd(20)} ${e.kind.padEnd(12)} ${e.actor.padEnd(6)} ${detail}`,
      );
    }
    break;
  }

  case "link": {
    const caseId = args[1];
    if (!caseId || caseId.startsWith("--")) die("usage: testigo link <caseId> [--term ID]");
    let termId = opt("--term");
    if (!termId) {
      const sessions = Object.entries(readState(ROOT).sessions ?? {});
      sessions.sort((a, b) => (b[1].lastTs ?? 0) - (a[1].lastTs ?? 0));
      termId = sessions[0]?.[0];
      if (!termId) die("no active session found — pass --term <sessionId>");
    }
    append(ROOT, { caseId, kind: "case_link", termId, actor: "system", payload: {} });
    const state = readState(ROOT);
    state.cases ??= {};
    state.cases[termId] = caseId;
    writeState(ROOT, state);
    console.log(`linked session ${termId} → ${caseId}`);
    break;
  }

  case "verify": {
    const r = verifyChain(ROOT);
    if (r.ok) {
      console.log(`chain ok: ${r.total} events${r.tornTail ? " (torn tail tolerated)" : ""}`);
    } else {
      console.log(`chain BROKEN at seq ${r.brokenAtSeq} (${r.total} lines)`);
      process.exit(1);
    }
    break;
  }

  case "export": {
    const caseId = opt("--case", null);
    const outDir = path.resolve(opt("--out", path.join(ROOT, "proofpacks")));
    const redactSeqs = (opt("--redact", "") || "")
      .split(",")
      .filter(Boolean)
      .map((s) => parseInt(s, 10));
    const tsa = opt("--tsa", null);
    if (!flag("--yes")) {
      // Pre-sign review: everything the packet would contain, so the human
      // can mark events for redaction BEFORE anything is signed.
      const pv = preview(ROOT, caseId);
      console.log(`pre-sign review — ${caseId ?? "full ledger"} (${pv.entries.length} entries):\n`);
      for (const e of pv.entries) {
        const mark = redactSeqs.includes(e.seq) ? "REDACT" : e.autoRedacted ? "auto-redacted" : e.stub ? "stub" : "";
        const excerpt = e.stub ? "(other case — linkage only)" : e.line.slice(0, 100);
        console.log(`${String(e.seq).padStart(4)}  ${e.kind.padEnd(12)} ${mark.padEnd(14)} ${excerpt}`);
      }
      console.log(
        `\nnothing signed. Re-run with --yes to sign & write` +
          ` (add --redact seq,seq to exclude event contents; hashes and linkage stay verifiable).`,
      );
      break;
    }
    const sum = await exportPacket(ROOT, { caseId, outDir, redactSeqs, tsa });
    console.log(`packet:   ${sum.path}`);
    console.log(`verifier: ${sum.verifier}`);
    console.log(
      `events: ${sum.events} · stubs: ${sum.stubs} · redactions: ${sum.redactions}` +
        (sum.timestamped ? ` · timestamped (RFC 3161)` : ""),
    );
    console.log(`key id: ${sum.keyId}  (share out-of-band — it is the receiver's trust anchor)`);
    break;
  }

  case "verify-packet": {
    const file = args[1];
    if (!file) die("usage: testigo verify-packet <file>");
    const r = verifyPacket(JSON.parse(fs.readFileSync(file, "utf8")));
    console.log(JSON.stringify({ ...r, statement: undefined }, null, 2));
    process.exit(r.valid ? 0 : 1);
    break;
  }

  case "key": {
    const k = keyInfo();
    console.log(`key id:     ${k.keyId}`);
    console.log(`public key: ${k.publicKey}`);
    console.log(`seed file:  ${k.file}  (0600 — treat like an SSH key)`);
    break;
  }

  default:
    console.log(HELP);
    process.exit(cmd && cmd !== "help" && cmd !== "--help" ? 1 : 0);
}
