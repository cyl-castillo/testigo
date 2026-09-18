# testigo-cli

Ambient intent-to-proof capture for [Claude Code](https://claude.com/claude-code),
speaking the [Testigo protocol](../SPEC.md). Zero dependencies, Node ≥ 20.
*Witness, not gatekeeper*: it records; it never orchestrates or blocks.

## Install as a Claude Code plugin (recommended)

```
/plugin marketplace add cyl-castillo/testigo
/plugin install testigo@testigo
```

Witnessing starts with your next session — the plugin wires the four capture
hooks automatically and adds three commands: `/testigo:status` (chain health
+ recent evidence), `/testigo:link` (bind the session to a case) and
`/testigo:export` (pre-sign review, then sign). Use the plugin **or**
`testigo init` below, not both — doubling the hooks records every event twice.

## Or install the hooks by hand

```
cd your-project
node /path/to/testigo/cli/bin/testigo.mjs init
# work with Claude Code as usual…
testigo log                      # see the evidence accumulate
testigo link jira:PROJ-42        # bind the session to a requirement
testigo export --case jira:PROJ-42          # pre-sign review (nothing signed)
testigo export --case jira:PROJ-42 --yes    # sign & write the proof packet
```

`init` wires six hooks (SessionStart, UserPromptSubmit, PreToolUse,
PostToolUse, PostModelSwitch, Stop) into `.claude/settings.json` (`--user`
for `~/.claude/settings.json`, `--print` to just look). From then on every
session start (engine, and the model when Claude Code sends it), prompt
(with the sha256 of the `CLAUDE.md` / `.claude/CLAUDE.md` / `AGENTS.md`
present in its cwd at that moment), tool call, tool result, model switch and
turn end lands in a per-project, hash-chained, append-only ledger under
`~/.local/share/testigo/` — outside the repo, never pushed. Hook failures
never break a session (exit 0 always; `TESTIGO_DEBUG=1` to see them).

Exports are [proof packets](../SPEC.md#2-the-proof-packet): a DSSE-signed
in-toto statement anyone verifies with the
[standalone verifier](../verifier/testigo-verifier.html) (written alongside
each packet), `testigo verify-packet`, or any DSSE tooling.
`--tsa https://freetsa.org/tsr` adds an RFC 3161 timestamp over the
signature (§2.5 — the TSA sees a signature hash, never content).
`--redact seq,seq` excludes event contents while keeping the chain
verifiable; the pre-sign review shows everything a packet would contain
*before* anything is signed. Every packet declares the
[process context](../SPEC.md#26-process-context-optional-additive--v02)
(spec §2.6) **derived from the ledger**: harness and engine, the models seen
in `session_start` / `model_switch`, the instruction-file digests the
prompts ran under, and the session window (which any verifier checks against
the events). `--owner login|email` (default: the project's `git config
user.email`) and `--model provider/name` (the model you asked for) are the
two things you declare on top.

## What this captures — and what it doesn't

Honesty first (it's the protocol's house style):

- **Captured:** session starts (`session_start`: engine, model when
  reported), human prompts (with instruction-file digests), agent tool
  calls (`tool_call`), tool results, model switches (`model_switch`), turn
  ends, case links —
  bound to turns by the **engine's session id**, which is stronger than the
  reference implementation's same-terminal heuristic but still not
  cryptographic: the hook trusts what the engine sends.
- **Not captured:** human approval decisions. Claude Code hooks don't
  expose the permission dialog, so ledgers from this CLI contain no
  `approval_request`/`approval_decision` events. Producers that sit in the
  permission path (e.g. [agent-console](https://github.com/cyl-castillo/agent-console))
  capture those.
- **Key storage:** an 0600 file (`~/.config/testigo/signing.key`), not an
  OS keychain — a zero-dependency CLI can't reach one. Treat it like an SSH
  key. The receiver's trust anchor is unchanged: the **key id**, compared
  out-of-band (`testigo key`).
- The ledger is **tamper-evident, not tamper-proof** — same as everywhere
  else in Testigo (§3).

## Correctness

`npm test` runs the tail-recovery regression tests and the end-to-end suite: hook capture (including
interleaved sessions and a crash-torn tail healing), case linking, export
with auto + manual redaction and out-of-case stubs, verification by both
this CLI's verifier and the [conformance suite's](../conformance/)
independent one — and requires the CLI verifier to reproduce the manifest
verdict on **every conformance vector**. Concurrent hook appends are
serialized by an advisory lock (parallel tool calls are real; a fork in the
chain would be corruption).

Ledger reads never modify the file. A complete final JSON record without a
newline is retained; the next append adds and syncs its separator first. An
unparseable final fragment without a newline is reported as a torn tail;
the next append truncates only that fragment and syncs the repair, preserving
all preceding bytes. Unparseable newline-terminated records (including two
concatenated events) are corruption and stop reading/appending without repair.
Whitespace-only lines remain ignored and their bytes are preserved.

To detect a ledger damaged by the old concatenation bug, run `testigo verify`
in the project (or pass `--root DIR`). It exits nonzero and reports the
offending physical line's zero-based index, including blank lines in the
count. Hooks still exit 0 on errors and show diagnostics only with
`TESTIGO_DEBUG=1`, so recording remains blocked until the ledger is repaired.
There is no automatic repair command for this corruption. Stop writers and
back up the project's ledger before repairing it manually: insert a single
newline at the `}{` boundary between the two complete event objects, preserving
all other bytes. Do not replace every `}{`: that text can also occur inside a
payload string. Run `testigo verify` again to check the restored hashes and
chain before resuming capture. Events already discarded by the old recovery
cannot be restored by splitting a line.

Appends resume short writes at byte offsets and sync the complete record and
newline before returning success. Write or sync failures propagate; a fully
written event can remain even if append reports failure, and recovery retains
it. Retrying an unsuccessful append is therefore not an exactly-once operation.
