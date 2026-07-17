# Predicate type: Session Chain

Type URI: https://in-toto.io/attestation/session-chain/v0.1 (proposed)

Version: 0.1.0 (draft)

## Authors

- Carlos Castillo (@cyl-castillo)

> **Status: DRAFT for discussion** — written for
> [in-toto/attestation#554](https://github.com/in-toto/attestation/issues/554),
> where a decision / session-chain / observed-effect / decision-input
> decomposition of AI-agent evidence emerged. This document is the
> session-chain member of that family. It derives from the
> [Testigo protocol](https://github.com/cyl-castillo/testigo) (predicate
> `https://github.com/cyl-castillo/testigo/attestation/v0.1`), which serves as
> its reference implementation and conformance corpus.

## Purpose

To attest a contiguous segment of an append-only, hash-chained event ledger
recording one thread of human-directed AI-agent work: the originating human
intent (prompt), human approval decisions, the agent's tool activity, and the
session-level outcome, with per-event redaction that preserves chain linkage.

Per-call records answer "was this call authorized" (agent-decision) and "what
was observed to happen" (observed-effect). The session chain binds the
*endpoints* those records cannot reach: which human intent originated the
work, and what the session produced end to end — while carrying the
intermediate events in a tamper-evident chain.

## Use Cases

1. **Compliance evidence for agent-performed changes.** EU AI Act art. 12
   (decision reconstruction: input context, executing system, actions,
   results) and art. 14 (human oversight: what was asked, what a human
   decided, and why — durably). A signed session chain is a portable record a
   deployer can hand an auditor without granting access to internal systems.
2. **Change provenance beyond the build.** SLSA provenance attests how an
   artifact was built; the session chain attests how the *change itself* came
   to be: the prompt or ticket, the approvals, and the working-tree diff of
   each agent turn.
3. **Selective disclosure.** A producer can publish a packet's digest as a
   commitment, then disclose the packet later with per-event redaction —
   receivers verify chain linkage across redacted events while their content
   is explicitly reported as unverifiable, never silently passed.
4. **Composition.** By content address, a session chain's events can be
   cross-referenced with agent-decision statements (authority transitions),
   observed-effect records (independent vantage), and decision-input records
   (what evidence the agent saw), without any of the four absorbing the
   others' job.

## Prerequisites

The [in-toto Attestation Framework](https://github.com/in-toto/attestation/tree/main/spec)
and familiarity with in-toto Statement v1. The ledger format and chain rules
are defined inline below; the normative long-form specification, a JSON
schema, golden conformance vectors and three independent verifier
implementations live in the [Testigo repository](https://github.com/cyl-castillo/testigo).

## Model

A **ledger** is a per-project, append-only UTF-8 JSONL file: one event per
line. Every event carries `seq` (0-based, strictly incrementing), `prevHash`
(the previous event's `hash`; `"genesis"` for seq 0) and `hash` — lowercase
hex sha256 over the exact line bytes with the `hash` value emptied (`"hash":""`
as the final member). Verification is **byte-exact**: no canonicalization is
needed because the bytes hashed are the bytes stored. The corollary is a
deployment rule: raw bytes must travel intact — any pipeline that reparses
and re-emits lines (log shippers, SIEM ingest, pretty-printers) breaks
recomputation while preserving JSON semantics.

A **turn** is one unit of agent work (human prompt → engine stop). A **case**
is an intent thread grouping turns (e.g. `jira:PROJ-1`, `github:org/repo#5`,
or a producer-scoped fallback). The event→turn binding is **declared, not
cryptographic**: producers bind by engine session id or terminal heuristics
and MUST NOT present the binding as stronger than it is.

The predicate carries a contiguous ledger segment as three entry forms:

- **Full event** — the raw line, byte-exact; content hash recomputable.
- **Redacted event** — the line with content replaced; `seq`/`prevHash`/`hash`
  are preserved, so linkage verifies while content recomputation is
  impossible *by design* and MUST be reported as such.
- **Stub** — `seq`/`prevHash`/`hash`/`kind` only, for in-range events that
  belong to another case (Merkle-style pruning): linkage verifies, nothing
  else is shared.

**Vantage, stated plainly:** the entire ledger is producer-reported. A valid
statement proves the signer exported this internally-consistent segment and
that shared content is unmodified since export. It does **not** prove
completeness (a producer can omit events before sealing), per-event timestamp
accuracy, or that the events reflect what an independent observer would have
seen. Consumers MUST NOT claim otherwise; an observed-effect record from an
independent vantage is the composing answer to that gap.

## Schema

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "jira:PROJ-1", "digest": { "sha256": "<hex>" } }],
  "predicateType": "https://in-toto.io/attestation/session-chain/v0.1",
  "predicate": {
    "caseId": "jira:PROJ-1",
    "project": "my-service",
    "exportedAt": "2026-07-17T12:00:00Z",
    "generator": "testigo-cli/0.1.0",
    "range": { "fromSeq": 3, "toSeq": 9, "prevHashBefore": "<hex>" },
    "ledgerHead": { "seq": 41, "hash": "<hex>" },
    "redactionCount": 1,
    "events": [
      { "line": "<raw ledger line, byte-exact>", "redacted": false },
      { "line": "<line with content replaced>", "redacted": true },
      { "stub": { "seq": 5, "prevHash": "<hex>", "hash": "<hex>", "kind": "prompt" } }
    ]
  }
}
```

### Parsing Rules

- Consumers MUST ignore unknown predicate fields and unknown event kinds:
  the chain verifies regardless (hashing is content-agnostic). Following the
  monotonic principle, unknown fields or kinds MUST NOT cause a policy to
  pass that would not otherwise pass — policy is satisfied only by evidence
  that is present and verifiable; absence and redaction never satisfy a
  requirement.
- The **subject digest** is sha256 (lowercase hex) over the UTF-8 bytes of
  the compact JSON serialization of `predicate.events` exactly as embedded
  (no whitespace, non-ASCII unescaped, member order preserved).
- Ledger lines are opaque byte strings from the predicate's point of view;
  their internal fields (including epoch-millisecond `ts` values) are
  producer content governed by the ledger format, not predicate fields —
  they cannot be rewritten to other conventions without destroying the
  hashes that make the record verifiable.

### Fields

`caseId` _string_, _optional_

The intent thread this segment was exported for. Absent (or null) means the
segment covers the whole ledger. Producers SHOULD use tracker-qualified
identifiers (`jira:KEY`, `github:org/repo#N`) when the case is bound to an
external requirement.

`project` _string_, _optional_

Producer-scoped project name (informative).

`exportedAt` _string (RFC 3339, "Z")_, _required_

When the producer sealed and signed this segment. This timestamps the
*export*, not the events; producers MAY additionally attach an RFC 3161
token over the envelope signature (outside the predicate) for third-party
proof of existence.

`generator` _string_, _optional_

Producing software and version.

`range` _object_, _required_

`fromSeq` _integer_ and `toSeq` _integer_ delimit the segment;
`prevHashBefore` _string_ is the `hash` of the event immediately before
`fromSeq` (`"genesis"` when `fromSeq` is 0), anchoring the segment's start.

`ledgerHead` _object_, _optional_

`{seq, hash}` of the producing ledger's tail at export time (informative;
verifiable against out-of-band anchors such as git refs or commit trailers
when the producer publishes them).

`redactionCount` _integer_, _required_

Number of redactions applied before signing. MUST equal the count evident
from `events`; a mismatch is a verification failure.

`events` _array_, _required_

The segment entries, in ledger order, each one of the three forms in the
Model section. Linkage MUST hold across every entry: each entry's `prevHash`
equals the previous entry's `hash`, starting from `range.prevHashBefore`.

**Event kinds** (open set; informative payloads): `prompt` (human intent,
opens a turn), `approval_request` / `approval_decision` (human-in-the-loop
oversight; decision payload `{approvalId, tool, decision: allow|deny|ask,
reason}` — field-compatible with the agent-decision predicate's
`decision`/`reason` so the two families do not drift), `tool_call`,
`tool_result`, `snapshot` (working-tree checkpoint), `turn_end` (closes a
turn; carries the turn's file diff), `case_link`, `job_run`.

### Verification

A verifier MUST: (1) verify the envelope signature; (2) recompute the
subject digest over `predicate.events`; (3) walk linkage across all entries
from `range.prevHashBefore`; (4) recompute content hashes for non-redacted
full events; (5) report redacted and stub entries visibly — never silently
pass them. A valid statement means exactly what the Model section's vantage
paragraph says, and no more. Golden vectors — including
valid-signature-around-internal-defect cases (signed-over broken digest,
linkage and content hashes: a green signature is not a green verdict) — are
published in the [Testigo conformance suite](https://github.com/cyl-castillo/testigo/tree/main/conformance).

## Example

See [`examples/demo.proofpack.json`](https://github.com/cyl-castillo/testigo/blob/main/examples/demo.proofpack.json)
for a complete signed packet (with a redacted event, a stub and an RFC 3161
timestamp) verifiable in the
[browser verifier](https://cyl-castillo.github.io/testigo/verifier/testigo-verifier.html),
and [`examples/fixy-deploy-verification.proofpack.json`](https://github.com/cyl-castillo/testigo/blob/main/examples/fixy-deploy-verification.proofpack.json)
for a redacted statement from a real production deploy (human intent, three
human approvals, empty turn diff — read-only, provably).

## Changelog and Migrations

Derives from the Testigo protocol predicate
`https://github.com/cyl-castillo/testigo/attestation/v0.1`, which is shipping
in two producers (agent-console ≥ 0.47.0; testigo-cli) and three verifier
implementations. Differences in this proposal: the predicate type URI, and
`exportedAt` (RFC 3339) replacing `exportedAtMs` (epoch milliseconds) per
in-toto timestamp conventions. If vetted, Testigo's next format version
adopts this predicate type as-is.
