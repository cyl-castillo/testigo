# @testigo/core

The engine-neutral reference core of the [Testigo protocol](../../SPEC.md).
It knows nothing about Claude Code, Codex or any other engine: adapters feed
it events, it keeps the ledger honest and exports what the spec calls a
proof packet.

| module | what it owns |
|---|---|
| `ledger.mjs` | per-project append-only JSONL ledger, sha256 hash chain, torn-tail healing, ledger lock, case binding, `verifyChain` |
| `export.mjs` | pre-sign review, auto/manual redaction, case pruning to stubs, process context (§2.6), DSSE Ed25519 signing, in-toto Statement, local key |
| `verify.mjs` | packet verification (§2.4) as the CLI performs it |
| `rfc3161.mjs` | RFC 3161 timestamp request/response over the DSSE signature (§2.5) |
| `evidence.mjs` | `external_evidence` commitments to records held elsewhere (§1.7) |

Zero dependencies, Node ≥ 20. `private` until the per-engine plugins land;
plugins ship a byte-identical copy under `<plugin>/vendor/core/`
(`node scripts/vendor.mjs sync|check`) because Claude Code installs only a
plugin's own directory.

Tests that exercise this core directly live in `conformance/hash.test.mjs`
and `conformance/validation-test.mjs` (against the reference verifier) and in
`cli/` (end to end through the Claude Code adapter).
