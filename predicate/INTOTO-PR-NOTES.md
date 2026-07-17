# Notes for the in-toto/attestation PR (not part of the predicate doc)

Draft PR body answering the four foundational questions from
`docs/new_predicate_guidelines.md`, plus submission checklist. The predicate
doc itself is [session-chain.md](session-chain.md); the protobuf is
[session_chain.proto](session_chain.proto).

## What's your use case?

Human-directed AI coding agents (Claude Code, Codex, and the tools around
them) perform work whose auditable unit is the *session*: a human intent
(prompt/ticket), human approval decisions along the way, the agent's tool
activity, and a session-level outcome (the turn's working-tree diff).
Deployers need a portable, signed, selectively-disclosable record of that
chain — EU AI Act art. 12 (decision reconstruction) and art. 14 (human
oversight) name the requirement directly. Discussion in
[#554](https://github.com/in-toto/attestation/issues/554) converged on a
four-family decomposition (decision-input / decision / session chain /
observed effect); this predicate is the session-chain member.

## Why don't existing predicates cover this?

- **SLSA Provenance** attests how an artifact was *built*; this attests how
  the *change* came to be (intent, oversight, actions, outcome) — upstream
  of any build.
- **Runtime Traces** captures system events (process/network/file) from a
  monitor's vantage; it has no notion of human intent, human approval, turn
  structure, hash-chained linkage across a session, or redaction with
  verifiable linkage.
- **agent-decision** (proposed, #554) records per-call authority
  transitions; it deliberately does not carry the session's endpoints (the
  originating intent, the outcome) nor the tamper-evident chain between them.
- **Test Result / SCAI / VSA** record verdicts or attribute assertions, not
  an append-only event chain with selective disclosure.

## What might the predicate look like?

See [session-chain.md](session-chain.md). Key properties: byte-exact hash
chain (no canonicalization; raw bytes are the identity), three entry forms
(full / redacted-with-linkage / stub), explicit producer-reported vantage
with MUST-level anti-overclaim language, and field compatibility with
agent-decision on `decision`/`reason`.

## What policy questions does it answer?

- Did a human originate this work, and what exactly did they ask for?
- Which tool uses did a human approve, and with what stated reason?
- What did the session change (turn diff), and was a given change covered by
  an approved, intent-bound session?
- Is the disclosed record internally consistent (linkage + content hashes),
  and precisely which parts were redacted rather than absent?
- Negative space (explicit): completeness and independent observation are
  NOT answerable from this predicate alone — compose with observed-effect
  evidence for that.

## Submission checklist (per new_predicate_guidelines.md)

- [ ] `spec/predicates/session-chain.md` (adapted from this repo's draft)
- [ ] Add to the predicates list in `spec/predicates/README.md`
- [ ] `protos/in_toto_attestation/predicates/session_chain/v1/` + generated
      bindings (repo has a `make protos` flow)
- [ ] Field names lowerCamelCase ✓ · timestamps RFC 3339 "Z" ✓ (predicate
      level; in-line event `ts` documented as opaque producer content)
- [ ] Monotonic-principle parsing rules ✓ (in doc)
- [ ] Valid subject types specified ✓ (in doc)
- [ ] After vetting: separate PR to in-toto.io for the URL redirect

## Open questions to settle with reviewers (Rul1an offered hands)

1. Name: `session-chain` vs `agent-session` vs `intent-to-proof`.
2. Whether the in-toto predicate should mandate tracker-qualified caseIds.
3. Whether `events[].line` opacity is acceptable to maintainers, or they
   want a structured event message (which would break byte-exact hashing —
   we would push back with the #554 canonicalization discussion).
4. Cross-referencing convention to agent-decision / observed-effect records
   (content address of the approval event? shared `traceParent`?).
