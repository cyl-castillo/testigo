# testigo-cli

Ambient intent-to-proof capture for [Claude Code](https://claude.com/claude-code),
speaking the [Testigo protocol](../SPEC.md). Zero dependencies, Node ≥ 20.
*Witness, not gatekeeper*: it records; it never orchestrates or blocks.

```
cd your-project
node /path/to/testigo/cli/bin/testigo.mjs init
# work with Claude Code as usual…
testigo log                      # see the evidence accumulate
testigo link jira:PROJ-42        # bind the session to a requirement
testigo export --case jira:PROJ-42          # pre-sign review (nothing signed)
testigo export --case jira:PROJ-42 --yes    # sign & write the proof packet
```

`init` wires four hooks (UserPromptSubmit, PreToolUse, PostToolUse, Stop)
into `.claude/settings.json` (`--user` for `~/.claude/settings.json`,
`--print` to just look). From then on every prompt, tool call, tool result
and turn end lands in a per-project, hash-chained, append-only ledger under
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
*before* anything is signed.

## What this captures — and what it doesn't

Honesty first (it's the protocol's house style):

- **Captured:** human prompts, agent tool calls (`tool_call`, a
  producer-added kind per §1.7), tool results, turn ends, case links —
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

`node test.mjs` runs the end-to-end suite: hook capture (including
interleaved sessions and a crash-torn tail healing), case linking, export
with auto + manual redaction and out-of-case stubs, verification by both
this CLI's verifier and the [conformance suite's](../conformance/)
independent one — and requires the CLI verifier to reproduce the manifest
verdict on **every conformance vector**. Concurrent hook appends are
serialized by an advisory lock (parallel tool calls are real; a fork in the
chain would be corruption).
