# testigo-cli

Ambient intent-to-proof capture for [Claude Code](https://claude.com/claude-code),
speaking the [Testigo protocol](../SPEC.md). Zero dependencies, Node ≥ 20.
*Witness, not gatekeeper*: it records; it never orchestrates or blocks.

## Install as a Claude Code plugin (recommended)

```
/plugin marketplace add cyl-castillo/testigo
/plugin install testigo@testigo
```

Witnessing starts with your next session — the plugin wires the capture
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
testigo export --case jira:PROJ-42          # save unsigned review; reports its path
# Open the reported JSON file and inspect its complete contents, or print it:
testigo export --review "/path/to/review-UUID.json"
testigo export --review "/path/to/review-UUID.json" --yes  # sign those exact bytes
```

`init` wires seven hooks (SessionStart, UserPromptSubmit, PreToolUse,
PostToolUse, PostToolUseFailure, PostModelSwitch, Stop) into `.claude/settings.json` (`--user`
for `~/.claude/settings.json`, `--print` to just look). From then on every
session start (engine, and the model when Claude Code sends it), prompt
(with the sha256 of the `CLAUDE.md` / `.claude/CLAUDE.md` / `AGENTS.md`
present in its cwd at that moment), tool call, tool result (failed ones
too), test/check run, model switch and turn end lands in a per-project, hash-chained, append-only ledger under
`~/.local/share/testigo/` — outside the repo, never pushed. Hook failures
never break a session (exit 0 always; `TESTIGO_DEBUG=1` to see them).

Exports are [proof packets](../SPEC.md#2-the-proof-packet): a DSSE-signed
in-toto statement anyone verifies with the
[standalone verifier](../verifier/testigo-verifier.html) (written alongside
each packet), `testigo verify-packet`, or any DSSE tooling.
`--tsa https://freetsa.org/tsr` adds an RFC 3161 timestamp over the
signature (§2.5 — the TSA sees a signature hash, never content).
`--redact seq,seq` replaces event **payloads**, keeping event metadata,
hashes and linkage. Generate a new review with these options, inspect it,
then sign the new file. Automatic and requested redactions are already
applied in the review, including to derived process context.

The pre-sign review is a complete unsigned in-toto statement saved as a
fresh `review-UUID.json` in `--out` (default: `./proofpacks`). The terminal
summary is **not** the review: open the JSON in an editor or print it using
`export --review FILE`. It contains all final event lines, linkage stubs,
and signed metadata without clipping. Event `line` strings preserve the
exact serialized event text; an editor's word wrap helps with long lines.
Review creates no signing key, signature, or TSA request.

For a read-only look, `export --review -` prints a fresh complete
post-redaction statement to stdout without creating a review file or output
directory. It accepts `--case`, `--redact`, `--owner`, and `--model` like a
normal export. It cannot be combined with `--yes`; to sign later, generate
and inspect a saved review using the normal export command.

`export --review FILE --yes` signs the file's exact bytes **after verifying
the current project ledger and matching the reviewed records against it**.
Use the same project directory or `--root DIR` used to prepare the review.
Every event and stub must retain its original `seq`, `prevHash`, and `hash`;
unredacted event lines must also match byte-for-byte. The range and saved
ledger-head anchor must still match. Redacted payloads remain producer
assertions: the check establishes their original ledger linkage, not their
hidden contents. These provenance checks run before the signing key is loaded.

Valid events appended while you review do not invalidate the snapshot.
A missing ledger, a broken chain, or missing/replaced reviewed records
prevent signing; a self-consistent review file alone is insufficient.
The signed statement is never regenerated: changes to git identity and
elapsed time do not alter it, and `exportedAtMs` still records when the
snapshot was prepared.
Changing `--case`, `--redact`, `--owner`, or `--model` requires generating
and inspecting a new review. Signing adds the public key and signature;
`--tsa` on the signing command adds a TSA response outside the statement.
For unattended use, `export ... --yes` without `--review` still exports
the current ledger directly and **skips review**.

Plain `export` writes a new review file on every call. Review files contain
the **post-redaction** statement and stay local until you remove them,
including earlier versions made before additional redactions. Post-redaction
does not mean safe to retain or share: patterns can miss sensitive text,
and retained metadata can still be private. Treat these files like the
packets themselves; do not commit or share them unintentionally.
Manual redaction does not remove identifiers or paths outside a payload;
inspect the remaining metadata before deciding to sign.

Every packet declares the
[process context](../SPEC.md#26-process-context-optional-additive--v02)
(spec §2.6) **derived from the ledger**: harness and engine, the models seen
in `session_start` / `model_switch`, the instruction-file digests the
prompts ran under, and the session window (which any verifier checks against
the events). `--owner login|email` (default: the project's `git config
user.email`) and `--model provider/name` (the model you asked for) are the
two things you declare on top.

## Test and check runs

When the agent runs a recognized test or check command (`cargo test`,
`npm test`, `pytest`, `go test`, `make check` and the rest of the
reference implementation's allow-list), the result is followed by a
`check_run` outcome event (SPEC §1.7): the command, `passed` or `failed`
as Claude Code reported it, the exit code when the failure text carries
it, the duration, and the sha256 of the full output. A reviewer reads it
before any prompt; a receiver holding the output recomputes the digest.
It is declared by the producer, like everything in the chain: `passed`
means the tool call completed, not that the suite is meaningful.

## External evidence

At every turn end the Stop hook commits the chain to the **Claude Code
transcript** Claude keeps on disk (path + sha256 of its bytes at that
moment): the same session transcripts Anthropic's Compliance API serves
centrally, so an auditor holding the platform's copy can recompute the
digest and match it. `testigo attach <file-or-url> --source
anthropic-compliance-api|github-agent-logs|file|url [--note …]` does the same
for any record you hold: a Compliance API export, a downloaded GitHub agent
session log, an artefact. The packet carries the commitment, never the
bytes; the verifier reports it and does not pretend to have checked the
record (spec §1.7).

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

`npm test` runs the end-to-end, pre-sign review and concurrency suites: hook capture (including
interleaved sessions and a crash-torn tail healing), case linking, export
with auto + manual redaction and out-of-case stubs, verification by both
this CLI's verifier and the [conformance suite's](../conformance/)
independent one — and requires the CLI verifier to reproduce the manifest
verdict on **every conformance vector**. CLI regression tests inspect long
prompt/tool content, metadata, automatic plus requested redactions, and
byte-for-byte equality between the saved review and the signed payload
after valid ledger appends and identity changes. They also check print-only
review and signing refusal for missing, corrupt, or replaced ledger records,
unrelated review files, and altered event/stub linkage. The concurrency suite launches 24
sessions in separate processes and checks event counts, turn/case bindings,
overlapping prompts/stops/links, append failures, and lock ownership. A
deterministic interleaving checks that a waiting hook selects its binding
only after acquiring the lock.

For cooperating writers on one host, each hook and case link selects its
binding and appends under the same per-project lock. Session and case state
is derived from the ledger within that lock; there is no second state write
that can overwrite another session or fail before an event is recorded.
Old `state/*.json` cache files are ignored and may be removed. Concurrent
events within one session follow lock acquisition order; the engine does
not provide enough information to reconstruct a different causal order.
This adds a state projection over the ledger already read for each append;
append work remains linear in ledger size.

Witnessing remains best effort: lock contention times out after five
seconds, and a crash or storage failure can still leave an event unrecorded
(a failed fsync can leave its durability uncertain). Hooks still exit 0;
`TESTIGO_DEBUG=1` reports failures. A live lock is never stolen based on age.
A confirmed dead owner can be reclaimed, but an ownerless lock (including
an old-version lock, or a crash between directory creation and owner
registration/removal) requires manual removal **after confirming no writer
is active**. PID reuse or an inaccessible owner can also prevent automatic
reclamation. Upgrade all writers together; mixed versions and shared
storage across hosts are not covered by this locking guarantee. Existing
torn-tail handling is unchanged.
