// Claude Code hook adapter: one command handles every hook event (the JSON
// on stdin carries hook_event_name). Ambient witnessing — the human works,
// the ledger fills.
//
// Binding honesty (§1.3): events bind to turns via the ENGINE's session_id
// (termId = sessionId = Claude Code's session_id), which is stronger than
// the reference implementation's same-terminal heuristic but still not
// cryptographic — the hook trusts what the engine sends it.
//
// What this adapter does NOT capture, said plainly: human approval
// decisions. Claude Code hooks expose prompts, tool calls, tool results and
// the stop signal — not the permission dialog's allow/deny/reason. Ledgers
// captured this way contain intent, actions, results and turn closure;
// approval_request/approval_decision events come from producers that sit in
// the permission path (e.g. agent-console).
//
// Process context (§2.6) is captured INTO the chain, not bolted on at
// export: `session_start` carries the engine and (when Claude Code sends it)
// the model, `model_switch` carries a mid-session change, and every prompt
// carries the digests of the instruction files present in its cwd at that
// moment. The export derives the predicate-level fields from these hashed
// lines, so what the packet declares about the run is what the run recorded.

import { append, bounded, caseFor, sha256hex } from "./ledger.mjs";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/// Claude Code hands every hook the path of the session transcript it keeps
/// on disk. At turn end we commit the chain to those bytes: the same session
/// transcripts Anthropic's Compliance API serves centrally to Enterprise
/// orgs, so an auditor holding the platform's copy can recompute the digest
/// and match it to the packet. Digest of the file as it was at turn end —
/// the transcript keeps growing afterwards; keep a copy if you need to
/// reproduce it later.
function transcriptEvidence(input) {
  const p = input.transcript_path;
  if (typeof p !== "string" || !p) return null;
  try {
    const buf = fs.readFileSync(p);
    return { source: "claude-code-transcript", uri: p, sha256: sha256hex(buf), bytes: buf.length };
  } catch {
    return null;
  }
}

/// Instruction files an agent reads implicitly. Hashed at prompt time —
/// the bytes the agent actually ran under, not whatever is on disk later.
export const INSTRUCTION_FILES = ["CLAUDE.md", ".claude/CLAUDE.md", "AGENTS.md"];

export function instructionContext(root) {
  const out = [];
  for (const rel of INSTRUCTION_FILES) {
    try {
      out.push({ uri: rel, sha256: sha256hex(fs.readFileSync(path.join(root, rel))) });
    } catch {
      // absent or unreadable: not an instruction the agent had
    }
  }
  return out;
}

/// Does this Bash command run a test/check suite? Same conservative
/// allow-list as the reference implementation (agent-console): a hit adds a
/// `check_run` outcome event beside the tool result (§1.7); a miss records
/// nothing extra. Matches a runner at the start of a shell word.
const CHECK_RUNNERS = [
  String.raw`cargo\s+(test|clippy|check|fmt\s+--check)`,
  String.raw`(npm|pnpm|yarn|bun)\s+(test|run\s+(test|tests|lint|typecheck|check|build|format:check))`,
  String.raw`npx\s+(vitest|jest|playwright|tsc|eslint|prettier\s+--check|mocha)`,
  String.raw`(vitest|jest|mocha|playwright\s+test|pytest|tox|nox|rspec|phpunit|dotnet\s+test|swift\s+test)`,
  String.raw`python(3)?\s+-m\s+(pytest|unittest)`,
  String.raw`go\s+(test|vet)`,
  String.raw`make\s+(test|check|lint)`,
  String.raw`(mvn|mvnw|\./mvnw)\s+(test|verify)`,
  String.raw`(gradle|gradlew|\./gradlew)\s+(test|check)`,
  String.raw`mix\s+test`,
  String.raw`bundle\s+exec\s+rspec`,
];
const CHECK_RE = new RegExp(String.raw`(^|[\s;&|(])(` + CHECK_RUNNERS.join("|") + String.raw`)(\s|$)`);

export function isCheckCommand(cmd) {
  return typeof cmd === "string" && CHECK_RE.test(cmd);
}

/// Text of a tool response or error, as the engine handed it to the hook.
function responseText(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/// A `check_run` outcome for a recognized runner (§1.7), or null.
function checkRun(input, failed, text) {
  const command = input.tool_input && typeof input.tool_input.command === "string" ? input.tool_input.command : "";
  if (input.tool_name !== "Bash" || !isCheckCommand(command)) return null;
  const b = bounded(command);
  const payload = {
    command: b.text,
    ...(b.truncated ? { truncated: true } : {}),
    status: failed ? "failed" : "passed",
  };
  if (failed) {
    // Claude Code's failure text starts with "Exit code N" for shell commands.
    const m = /^Exit code (\d+)/.exec(text.split("\n")[0].trim());
    if (m) payload.exitCode = parseInt(m[1], 10);
  }
  if (text) payload.outputSha256 = sha256hex(Buffer.from(text, "utf8"));
  if (typeof input.duration_ms === "number") payload.durationMs = input.duration_ms;
  if (typeof input.tool_use_id === "string" && input.tool_use_id) payload.toolUseId = input.tool_use_id;
  return payload;
}

/// Handle one hook invocation. The CLI catches failures and exits 0, so
/// witnessing never breaks the user's session (TESTIGO_DEBUG=1 shows errors).
export function handleHook(input) {
  const session = input.session_id;
  const root = input.cwd;
  if (!session || !root) return;
  if (!Object.hasOwn(hooksConfig(""), input.hook_event_name)) return;
  return append(root, (state) => hookEvent(input, state));
}

// Called under the ledger lock: no other hook/link can change the selected
// case or open turn before this event is durably appended.
function hookEvent(input, state) {
  const session = input.session_id;
  const root = input.cwd;
  const termId = session;
  const caseId = caseFor(root, termId, state);

  switch (input.hook_event_name) {
    case "SessionStart": {
      // Producer-added kind (§1.7): the engine this session runs in and, when
      // Claude Code includes it, the model — the provider facts APE asks for.
      return {
        caseId,
        kind: "session_start",
        termId,
        sessionId: session,
        actor: "system",
        payload: {
          engine: "claude-code",
          ...(typeof input.model === "string" && input.model ? { model: input.model } : {}),
          ...(typeof input.source === "string" && input.source ? { source: input.source } : {}),
        },
      };
    }
    case "PostModelSwitch": {
      const turnId = state.sessions[session]?.turnId;
      return {
        caseId,
        ...(turnId ? { turnId } : {}),
        kind: "model_switch", // producer-added kind (§1.7)
        termId,
        sessionId: session,
        actor: "system",
        payload: { from: input.from_model ?? null, to: input.to_model ?? null },
      };
    }
    case "UserPromptSubmit": {
      // A prompt opens a turn; a prompt on a session with an open turn
      // supersedes it (§1.3 — engines don't always emit stop).
      const turnId = crypto.randomUUID();
      const b = bounded(input.prompt ?? "");
      const context = instructionContext(root);
      return {
        caseId,
        turnId,
        kind: "prompt",
        termId,
        sessionId: session,
        actor: "human",
        payload: {
          prompt: b.text,
          ...(b.truncated ? { truncated: true } : {}),
          cwd: root,
          ...(context.length ? { context } : {}),
        },
      };
    }
    case "PreToolUse": {
      const turnId = state.sessions[session]?.turnId;
      const b = bounded(input.tool_input);
      return {
        caseId,
        ...(turnId ? { turnId } : {}),
        kind: "tool_call", // producer-added kind (§1.7): a tool invocation, approval-status unknown
        termId,
        sessionId: session,
        actor: "agent",
        payload: { tool: input.tool_name ?? "", input: b.text, truncated: b.truncated },
      };
    }
    case "PostToolUse":
    case "PostToolUseFailure": {
      // A tool that failed (a test suite exiting non-zero) reaches
      // PostToolUseFailure with the error text instead of a response.
      const failed = input.hook_event_name === "PostToolUseFailure";
      const turnId = state.sessions[session]?.turnId;
      const raw = failed ? input.error : input.tool_response;
      const b = bounded(raw);
      const base = { caseId, ...(turnId ? { turnId } : {}), termId, sessionId: session, actor: "agent" };
      const result = {
        ...base,
        kind: "tool_result",
        payload: { tool: input.tool_name ?? "", excerpt: b.text, truncated: b.truncated, ...(failed ? { failed: true } : {}) },
      };
      // Outcome event (§1.7): a recognized test/check runner leaves a
      // check_run beside its result, under the same binding and lock.
      const check = checkRun(input, failed, responseText(raw));
      return check ? [result, { ...base, kind: "check_run", payload: check }] : result;
    }
    case "Stop": {
      const open = state.sessions[session];
      const evidence = transcriptEvidence(input);
      const end = {
        caseId,
        ...(open?.turnId ? { turnId: open.turnId } : {}),
        kind: "turn_end",
        termId,
        sessionId: session,
        actor: "agent",
        payload: {},
      };
      // Both records use the same binding and lock; a new prompt cannot
      // interleave between the transcript commitment and its turn closure.
      return evidence ? [{ ...end, kind: "external_evidence", actor: "system", payload: evidence }, end] : end;
    }
    default:
      return; // unknown/unneeded hook events are ignored, never an error
  }
}

/// The hooks Claude Code needs (project or user settings.json). `command`
/// is how to reach this CLI on the machine.
export function hooksConfig(command, shell = "bash") {
  const h = [{ hooks: [{ type: "command", command, shell }] }];
  return { SessionStart: h, UserPromptSubmit: h, PreToolUse: h, PostToolUse: h, PostToolUseFailure: h, PostModelSwitch: h, Stop: h };
}
