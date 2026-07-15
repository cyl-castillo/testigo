# Testigo — From Intent to Proof

**Testigo** is an open protocol for traceability, compliance and verification of
actions executed by humans *and* AI agents, together.

Its purpose is to guarantee that every significant action can demonstrate:

- why it was performed;
- which human intent originated it;
- which requirement it was fulfilling;
- who — or which agent — executed it;
- what the human approved (and why);
- what evidence it produced;
- and what final result was deployed or used.

Testigo is **not** a task manager, a CI/CD platform, a coding agent or a payment
system. It is a **trust layer** that connects the original intent with the
execution and the verifiable evidence of the outcome. *Witness, not gatekeeper*:
it records; it never orchestrates or blocks.

## The chain

```
intent (prompt / ticket)
  → turn (agent works)
    → human approval (allow/deny + reason)
    → tool results
    → evidence (working-tree snapshots, files changed)
  → turn end
→ signed proof packet → anyone verifies, no install
```

Every link is an event in an append-only, sha256 hash-chained ledger (one per
project, local-first). A segment of that ledger exports as an
[in-toto Statement](https://in-toto.io) signed as a
[DSSE](https://github.com/secure-systems-lab/dsse) Ed25519 envelope — the
**proof packet** — verifiable with the standalone HTML verifier in this repo,
or any DSSE tooling.

## Quickstart: verify the example

1. Open [`verifier/testigo-verifier.html`](verifier/testigo-verifier.html) in a
   browser (no network, no install — everything runs locally via WebCrypto).
2. Drop [`examples/demo.proofpack.json`](examples/demo.proofpack.json) on it.
3. You should see: signature valid, subject digest OK, hash chain intact —
   including one **redacted** event (linkage verified, content declared
   unverifiable) and one **stub** (an out-of-case event pruned to hashes).

## Spec

The protocol is specified in [SPEC.md](SPEC.md) (v0.1, draft). The predicate
schema lives in [`schema/predicate-v0.1.schema.json`](schema/predicate-v0.1.schema.json).

Reference implementation: [agent-console](https://github.com/cyl-castillo/agent-console)
(≥ v0.48.0) — captures the ledger ambiently from Claude Code / Codex sessions
(prompts, approvals, tool results, per-turn diffs), exports and signs packets,
and stamps console-made commits with `Testigo-Case:` trailers resolved from
ledger evidence.

## Honesty by design

Testigo prefers a smaller true claim over a bigger false one:

- The local ledger is **tamper-evident, not tamper-proof** — signing happens at
  export, and a packet proves segment integrity + who signed it, not that the
  ledger is complete.
- The event→turn binding is **heuristic** (same terminal between a prompt and
  its stop), not cryptographic. The spec says so.
- Redacted events keep their original hashes: chain linkage stays verifiable,
  content verification is explicitly reported as unavailable.
- The packet embeds its public key for convenience; the **trust anchor is the
  key id compared out-of-band** with the publisher.

## Status

- Spec: v0.1 (draft — field names and predicate type are stable within v0.1).
- Reference implementation: shipping since agent-console v0.45.0 (ledger),
  v0.46.0 (turn results), v0.47.0 (packets + verifier), v0.48.0 (timelines +
  commit trailers).
- Roadmap: sigstore keyless signing, RFC 3161 timestamps, git-ref ledger
  anchoring, requirement links beyond Jira, cross-project cases.

## License

MIT — see [LICENSE](LICENSE).
