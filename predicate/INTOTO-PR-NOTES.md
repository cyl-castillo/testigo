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

## Conformance evidence (the bar #554 set for vetting a predicate)

The thread converged on a bar stricter than "the author's verifier passes":
a corpus owned by the spec, plus **at least two independently authored
checkers** in parity — dependency-freedom is not assumption-freedom, and
checkers sharing an author share its blind spots.

State of that evidence as of `e19a522`:

- **Corpus**: 17 parent vectors ([`conformance/`](../conformance/)) + 6
  session-chain vectors ([`vectors/`](vectors/)) instantiating this
  predicate's conventions; produced by one deterministic generator
  (`generate.mjs`, fixed timestamps, deterministic Ed25519 — regeneration is
  byte-identical), so the corpus can be re-homed under the spec repo without
  reproducibility loss.
- **Checker A**: `conformance/verify.mjs` (Node, zero deps) plus the browser
  verifier — same author as the spec.
- **Checker B**: written independently by
  [@Rul1an](https://github.com/Rul1an) from the spec text only, without
  reading this repo's code (Python stdlib, Ed25519 from RFC 8032). Parity:
  **11/11** on the parent suite at first run, **4/4** on the session-chain
  subset, and **17/17 + 6/6** after both sides' corrections landed.
- **What the cross actually produced** (parity alone would have hidden it):
  `redactionCount` was underspecified (normative in the draft, example-only
  in SPEC) and the migration fields (type URI, `exportedAt`) were
  instantiated but not guarded. Both were fixed in the spec, and the
  corresponding negatives exist because only the key holder can sign them.
- **Negatives separate lax from conforming**: three signed-over mutation
  vectors donated by Checker B's adversarial runs (injected event,
  duplicated entry, reserialized line) plus the two migration guards. The
  reserialized-line vector pins byte-exactness: a checker that canonicalizes
  before hashing cannot distinguish it.

Cross log: [testigo#1](https://github.com/cyl-castillo/testigo/issues/1).
If this goes in as a PR, @Rul1an is the second author of the independent
checker and co-signatory of the design decisions folded in from the cross
(subject rule, `enforce` semantics).

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
