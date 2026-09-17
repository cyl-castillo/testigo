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

import { append, bounded, caseFor, readState, sha256hex, writeState } from "./ledger.mjs";
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

/// Handle one hook invocation. Never throws in the hook path — witnessing
/// must never break the user's session (exit 0 always; failures are visible
/// with TESTIGO_DEBUG=1).
export function handleHook(input) {
  const session = input.session_id;
  const root = input.cwd;
  if (!session || !root) return;
  const termId = session;
  const caseId = caseFor(root, termId);
  const state = readState(root);
  state.sessions ??= {};

  switch (input.hook_event_name) {
    case "SessionStart": {
      // Producer-added kind (§1.7): the engine this session runs in and, when
      // Claude Code includes it, the model — the provider facts APE asks for.
      append(root, {
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
      });
      return;
    }
    case "PostModelSwitch": {
      const turnId = state.sessions[session]?.turnId;
      append(root, {
        caseId,
        ...(turnId ? { turnId } : {}),
        kind: "model_switch", // producer-added kind (§1.7)
        termId,
        sessionId: session,
        actor: "system",
        payload: { from: input.from_model ?? null, to: input.to_model ?? null },
      });
      return;
    }
    case "UserPromptSubmit": {
      // A prompt opens a turn; a prompt on a session with an open turn
      // supersedes it (§1.3 — engines don't always emit stop).
      const turnId = crypto.randomUUID();
      state.sessions[session] = { turnId, lastTs: Date.now() };
      writeState(root, state);
      const b = bounded(input.prompt ?? "");
      const context = instructionContext(root);
      append(root, {
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
      });
      return;
    }
    case "PreToolUse": {
      const turnId = state.sessions[session]?.turnId;
      const b = bounded(input.tool_input);
      append(root, {
        caseId,
        ...(turnId ? { turnId } : {}),
        kind: "tool_call", // producer-added kind (§1.7): a tool invocation, approval-status unknown
        termId,
        sessionId: session,
        actor: "agent",
        payload: { tool: input.tool_name ?? "", input: b.text, truncated: b.truncated },
      });
      return;
    }
    case "PostToolUse": {
      const turnId = state.sessions[session]?.turnId;
      const b = bounded(input.tool_response);
      append(root, {
        caseId,
        ...(turnId ? { turnId } : {}),
        kind: "tool_result",
        termId,
        sessionId: session,
        actor: "agent",
        payload: { tool: input.tool_name ?? "", excerpt: b.text, truncated: b.truncated },
      });
      return;
    }
    case "Stop": {
      const open = state.sessions[session];
      if (open) {
        delete state.sessions[session];
        writeState(root, state);
      }
      const evidence = transcriptEvidence(input);
      if (evidence) {
        append(root, {
          caseId,
          ...(open?.turnId ? { turnId: open.turnId } : {}),
          kind: "external_evidence", // producer-added kind (§1.7)
          termId,
          sessionId: session,
          actor: "system",
          payload: evidence,
        });
      }
      append(root, {
        caseId,
        ...(open?.turnId ? { turnId: open.turnId } : {}),
        kind: "turn_end",
        termId,
        sessionId: session,
        actor: "agent",
        payload: {},
      });
      return;
    }
    default:
      return; // unknown/unneeded hook events are ignored, never an error
  }
}

/// The hooks Claude Code needs (project or user settings.json). `command`
/// is how to reach this CLI on the machine.
export function hooksConfig(command) {
  const h = [{ hooks: [{ type: "command", command }] }];
  return { SessionStart: h, UserPromptSubmit: h, PreToolUse: h, PostToolUse: h, PostModelSwitch: h, Stop: h };
}
