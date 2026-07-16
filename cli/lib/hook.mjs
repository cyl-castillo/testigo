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

import { append, bounded, caseFor, readState, writeState } from "./ledger.mjs";
import crypto from "node:crypto";

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
    case "UserPromptSubmit": {
      // A prompt opens a turn; a prompt on a session with an open turn
      // supersedes it (§1.3 — engines don't always emit stop).
      const turnId = crypto.randomUUID();
      state.sessions[session] = { turnId, lastTs: Date.now() };
      writeState(root, state);
      const b = bounded(input.prompt ?? "");
      append(root, {
        caseId,
        turnId,
        kind: "prompt",
        termId,
        sessionId: session,
        actor: "human",
        payload: { prompt: b.text, ...(b.truncated ? { truncated: true } : {}), cwd: root },
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
  return { UserPromptSubmit: h, PreToolUse: h, PostToolUse: h, Stop: h };
}
