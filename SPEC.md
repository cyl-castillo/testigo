# Testigo protocol — v0.2 (draft)

> **v0.2 is additive.** It adds the `session_start` / `model_switch` /
> `tool_call` event kinds and the `prompt.payload.context` member (§1.7),
> and the **process context** predicate fields (§2.6): `provider`,
> `contextArtifacts`, `startTimestamp` / `endTimestamp`, `owner`. The packet
> `format` (`testigo-proofpack/v0.1`) and the predicate type URI are
> unchanged (§5): every v0.1 packet is a valid v0.2 packet, and a v0.1
> verifier ignores the new fields. The fields mirror the *Agentic Process
> Evidence* proposal (FINOS ai-governance-framework#384) so a packet can be
> referenced as an APE session log — see
> [docs/ape-mapping.md](docs/ape-mapping.md).

Testigo defines two artifacts and the rules connecting them:

1. **The ledger** — a per-project, append-only, hash-chained event log capturing
   the intent-to-proof chain as it happens.
2. **The proof packet** — a signed, portable export of a ledger segment,
   verifiable without the producing software.

Words in **bold capitals** (MUST, SHOULD, MAY) follow RFC 2119.

---

## 1. The ledger

### 1.1 Encoding

A ledger is a UTF-8 [JSONL](https://jsonlines.org/) file: one event per line,
append-only. Producers MUST NOT rewrite past lines except for the torn-tail
healing in §1.5.

### 1.2 Event structure

```json
{"seq":0,"ts":1784112000000,"caseId":"jira:DEMO-1","turnId":"6c0f…","kind":"prompt","termId":"t-1","sessionId":"s-1","actor":"human","payload":{…},"prevHash":"genesis","hash":"e3b0…"}
```

| Field | Type | Req | Meaning |
|---|---|---|---|
| `seq` | integer | yes | 0-based, strictly `prev.seq + 1` |
| `ts` | integer | yes | epoch milliseconds (producer's local clock; `0` if unknown) |
| `caseId` | string | yes | the intent thread (§1.4) |
| `turnId` | string | no | the turn this event happened inside (§1.3) |
| `kind` | string | yes | event kind (§1.7) |
| `termId` | string | no | producer-scoped terminal/session binding |
| `sessionId` | string | no | engine conversation id (e.g. Claude Code session) |
| `actor` | string | yes | `human`, `agent`, or `system` |
| `payload` | object | yes | kind-specific content (§1.7) |
| `prevHash` | string | yes | `hash` of the previous event; `"genesis"` for `seq` 0 |
| `hash` | string | yes | this event's content hash (§1.5) |

Optional fields are **omitted** when absent (never `null`). `hash` MUST be the
final member of the serialized object.

### 1.3 Turns

A **turn** is one unit of agent work: it opens at a human prompt and closes at
the engine's stop signal. All events produced in between on the same `termId`
carry the turn's `turnId`.

> **Declared limitation:** the event→turn binding is *heuristic* — same
> terminal between a prompt and its stop — not cryptographic. Verifiers and
> consumers MUST NOT present it as a cryptographic association.

A new prompt on a terminal with an open turn implicitly supersedes it (engines
don't always emit stop). A `turn_end` without a known open turn MAY carry no
`turnId`.

### 1.4 Cases

A **case** is an intent thread grouping turns. `caseId` values:

- `jira:<KEY>` — bound to an external requirement (ticket) via a `case_link`
  event. Producers MAY define analogous prefixes for other trackers.
- `term:<termId>` — fallback: the terminal's own thread.
- `job:<jobId>` — scheduled/automated runs.
- `unbound` — no attribution available.

A `case_link` event binds a `termId` to a case; the binding applies to that
terminal's subsequent events and MUST be recoverable by replaying the ledger.

### 1.5 Hash chain

```
hash = lowercase hex sha256( line bytes with the hash value emptied )
```

Precisely: serialize the event with `hash` set to the empty string (`"hash":""`
as the final member), take sha256 of those exact UTF-8 bytes, store the hex
digest as `hash`, then append the line. `prevHash` MUST equal the previous
line's `hash` (`"genesis"` for the first event).

To recompute from a raw line, replace the *last* occurrence of `"hash":"…"` —
which is the final member — with `"hash":""` and hash the result. This makes
verification byte-exact without canonicalization machinery.

> **Deployment note:** byte-exactness holds exactly as far as the raw bytes
> travel intact. Any pipeline that reparses and re-emits ledger lines — log
> shippers, SIEM ingestion, pretty-printers — breaks hash recomputation even
> when it preserves JSON semantics. Ship the raw file (or the packet, which
> embeds lines verbatim); never a re-serialization.

The chain is **tamper-evident, not tamper-proof**: an actor with disk access
can rewrite the whole file consistently. Trust is established at packet export
(signature), not at rest.

**Torn tail:** a crash mid-append may leave a final unparseable line. Readers
MUST tolerate it; producers SHOULD heal it by truncating the torn final line
(atomically) before the next append. Unparseable lines anywhere else are
tampering and MUST be reported by verification.

### 1.6 Anchoring (optional, additive — since v0.2 of the reference impl)

Producers working inside a git checkout MAY anchor the ledger head after
each closing event (`turn_end`, `job_run`). Anchoring writes to the project's
repository, so it MUST be under the project owner's control — the reference
implementation makes it per-project opt-in (witnessing itself stays local and
on by default). Packets without anchors remain fully valid:

- **Local ref**: a blob `{"seq":N,"hash":"…","ts":T}` pinned at
  `refs/agent-console/testigo-head` in the checkout.
- **Distributed trailer**: commits made through the producer carry
  `Testigo-Head: <seq>:<hash>` (next to `Testigo-Case:`), so the anchor rides
  ordinary pushes into remote history and clones.

Rewriting the ledger consistently now also requires rewriting the ref and any
pushed commits that cite the old head. This strengthens tamper-EVIDENCE — it
is still not tamper-proof against an actor with full control of every copy.
Verifiers and auditors MAY cross-check a packet's `ledgerHead` against
anchored values found in refs or commit trailers.

### 1.7 Event kinds

| kind | actor | payload (informative) |
|---|---|---|
| `prompt` | human | `{prompt, skill?, cwd?}` — opens a turn |
| `approval_request` | agent | `{approvalId, tool, input (bounded), cwd?}` |
| `approval_decision` | human | `{approvalId, tool?, decision: allow\|deny\|ask, reason?}` |
| `tool_result` | agent | `{tool?, excerpt (bounded), truncated}` |
| `snapshot` | system | `{commitSha}` — working-tree checkpoint (git) |
| `turn_end` | agent | `{preSha?, postSha?, filesChanged?: [{status, path}], filesTruncated?}` — closes a turn |
| `case_link` | system | `{}` (binding carried by `caseId` + `termId`) |
| `job_run` | system | `{jobId, jobName, status, summary}` |
| `session_start` | system | `{engine, model?, source?}` — the engine a session runs in and, when the engine reports it, the model (v0.2) |
| `model_switch` | system | `{from, to}` — a mid-session model change (v0.2) |
| `tool_call` | agent | `{tool, input (bounded), truncated}` — a tool invocation whose approval status the producer cannot see (producers outside the permission path, e.g. testigo-cli) |
| `external_evidence` | system | `{source, uri, sha256, bytes, mediaType?, note?}` — a commitment to a record held elsewhere (v0.2): `source` names the system (`claude-code-transcript`, `anthropic-compliance-api`, `github-agent-logs`, `file`, `url`), `sha256` is over the bytes the producer saw |

**External evidence.** Platforms keep their own record of an agent session
— Claude Code writes a transcript on disk and Anthropic's Compliance API
serves the same transcripts centrally; GitHub links every agent commit to
its session log. An `external_evidence` event puts the digest of such a
record *inside the chain*, so a packet commits to it without carrying it:
a receiver who obtains the record from the platform recomputes the sha256
and knows it is the one this session pointed at. The digest binds the
bytes at capture time (a transcript keeps growing after a turn ends);
verifiers do not fetch anything and MUST NOT report the record as verified
— only the commitment is. testigo-cli records the Claude Code transcript at
every turn end and attaches any file or URL with `testigo attach`.

The `prompt` payload MAY carry `context: [{uri, sha256}]` (v0.2): the
instruction files (`CLAUDE.md`, `.claude/CLAUDE.md`, `AGENTS.md`, or the
producer's equivalents) present in the prompt's `cwd` **at prompt time**,
with the sha256 of their bytes. Hashing at capture — inside the chain — is
what lets the predicate-level `contextArtifacts` (§2.6) be *derived* rather
than asserted.

Payloads with unbounded inputs (tool inputs/outputs) MUST be size-bounded by
the producer; the reference implementation truncates to a marked preview.
Producers MAY add kinds; verifiers MUST ignore unknown kinds (the chain still
verifies — hashing is content-agnostic).

---

## 2. The proof packet

### 2.1 Envelope

A packet is a JSON document:

```json
{
  "format": "testigo-proofpack/v0.1",
  "envelope": {
    "payloadType": "application/vnd.in-toto+json",
    "payload": "<base64(statement)>",
    "signatures": [{ "keyid": "<sha256 hex of raw pubkey>", "sig": "<base64(ed25519 signature)>" }]
  },
  "publicKey": "<base64(raw 32-byte ed25519 public key)>"
}
```

The envelope is standard [DSSE](https://github.com/secure-systems-lab/dsse):
the signature is Ed25519 over the pre-authentication encoding

```
PAE = "DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
```

with lengths as ASCII decimal byte counts and `payload` as raw (decoded) bytes.

`publicKey` is a convenience copy. **The trust anchor is `keyid`** — sha256 of
the raw public key — compared with the publisher out-of-band. Verifiers MUST
surface this distinction.

### 2.2 Statement

The payload is an [in-toto Statement v1](https://in-toto.io/Statement/v1):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<caseId or 'ledger'>", "digest": { "sha256": "<events digest>" } }],
  "predicateType": "https://github.com/cyl-castillo/testigo/attestation/v0.1",
  "predicate": { … }
}
```

The subject digest is sha256 (hex) over the UTF-8 bytes of the **compact JSON
serialization of `predicate.events`** exactly as embedded in the statement
(no whitespace, non-ASCII unescaped, member order preserved). JSON parsers
that preserve object member order (JavaScript, Python) reproduce these bytes
by re-serializing the parsed array compactly.

### 2.3 Predicate

See [`schema/predicate-v0.1.schema.json`](schema/predicate-v0.1.schema.json).

```json
{
  "caseId": "jira:DEMO-1",
  "project": "demo",
  "exportedAtMs": 1784112999000,
  "generator": "agent-console/0.48.0",
  "range": { "fromSeq": 0, "toSeq": 5, "prevHashBefore": "genesis" },
  "ledgerHead": { "seq": 41, "hash": "…" },
  "redactionCount": 1,
  "events": [ … ]
}
```

`events` entries are one of:

- **Full event** — `{ "line": "<raw ledger line, byte-exact>", "redacted": false }`
- **Redacted event** — `{ "line": "<line with secrets replaced>", "redacted": true }`.
  Redaction MUST NOT alter `seq`, `prevHash` or `hash`. Content hash
  recomputation is therefore impossible by design; linkage remains verifiable.
  `redacted` is a **producer assertion**: it claims content was replaced, it
  is not evidence that it was — a producer can mark an unaltered line
  redacted, and no verifier can tell. Consumers MUST NOT read the flag (or
  the count below) as more than the producer's own statement.
- **Stub** — `{ "stub": { "seq", "prevHash", "hash", "kind" } }` — an event
  inside the exported range that belongs to another case. Stubs preserve chain
  linkage while sharing nothing else (Merkle-style pruning).

`redactionCount` MUST equal the number of `events` entries carrying
`redacted: true`. **Stubs are not redactions** — a stub prunes an out-of-case
event to hashes, a redacted event keeps its frame with content replaced; the
count covers only the latter. Verifiers MUST treat a mismatch as a
verification failure (a signed-over miscount misrepresents what was withheld).

`range.prevHashBefore` is the `hash` of the event immediately before
`fromSeq` (`"genesis"` when `fromSeq` is 0), anchoring the segment's start.
`ledgerHead` reports the producing ledger's tail at export time (informative).

Producers MUST refuse to export a ledger whose chain does not verify.

### 2.3.1 Profile and structural requirements

The **Testigo profile** requires the exact `format`, DSSE `payloadType`,
statement `_type`, and `predicateType` shown in §2.1–§2.2. A signature over
a different type does not make it a Testigo attestation. Verifiers MUST reject
unsupported types; the packet MUST NOT select a more permissive profile.

The predicate MUST be an object with `project` and `generator` strings,
integer `exportedAtMs`, a `range` object and an `events` array, as required by
the published schema. `caseId` is optional (string or null). `ledgerHead` is
optional and informative: its optional `seq` and `hash` retain the schema's
integer-or-null and string-or-null types; it need not equal the segment tail.
For compatibility with the published Testigo schema, omitted
`redactionCount` means **zero**; a present value MUST be a non-negative
integer. This default does not permit omitting a nonzero count.

`range` is **inclusive and nonempty**: `fromSeq` and `toSeq` MUST be
non-negative integers with `fromSeq <= toSeq`, and
`events.length == toSeq - fromSeq + 1`. Every entry, including redacted
events and stubs, MUST have `seq == fromSeq + its zero-based array index`.
Thus the first and last sequences equal the range bounds and no sequence
can be skipped, duplicated or reordered. The supplied verifiers and schema
support exact sequence integers through `9007199254740991`; they reject
larger values rather than verify rounded JSON numbers. A segment may begin
after zero: its `prevHashBefore` MUST then be a lowercase 64-character
SHA-256 hex digest. When `fromSeq` is zero it MUST be `"genesis"`.

Each entry MUST match exactly one schema form: `{line, redacted}` with a
string and a boolean, or `{stub}` with an object. Entry wrappers are closed
as in the existing schema; unknown predicate fields, ledger fields, stub
fields and event kinds remain allowed. Parsed lines MUST carry the required
field types in §1.2, even when redacted; kind-specific payload content remains
informative. A stub requires `seq`, `prevHash`, and `hash`; its `kind` is
optional for compatibility with the published schema. Hashes are lowercase
64-character SHA-256 hex strings; `prevHash` may also be `"genesis"`.

`subject` MUST be a nonempty array of descriptors with a string `name` and
a nonempty `digest` object with string values. Testigo uses the first
descriptor's `digest.sha256` for the segment digest (§2.2). Extra descriptors
and descriptor fields are allowed. The separate session-chain draft has
different subject/evidence rules; it is not an alias for this profile.

The JSON schema covers predicate structure, not DSSE or statement identity,
signatures, parsed ledger lines, or cross-field equality. Passing schema
validation alone MUST NOT be reported as packet verification.

### 2.4 Verification algorithm

Given a packet, a verifier MUST:

1. Check `format` and require DSSE `payloadType` to be
   `application/vnd.in-toto+json` (failures `format`, `payloadType`).
2. Decode `publicKey`; compute `keyid` = sha256 hex; require it to equal
   `signatures[0].keyid`.
3. Verify the Ed25519 signature over `PAE(payloadType, payload)`.
4. Parse the statement; require `_type` = `https://in-toto.io/Statement/v1`
   and the Testigo `predicateType` from §2.2 (failures `statementType`,
   `predicateType`). Validate required fields, entry structure, inclusive
   range and every sequence per §2.3.1 (failures `predicate`, `subject`,
   `events`, `entry`, `range`, `sequence`, `redactionCount`). Recompute the
   subject digest over the compact serialization of `predicate.events`;
   require equality (`digest`).
5. Walk `events` in order, starting `prev = range.prevHashBefore`. For every
   entry (full, redacted, or stub): require `prevHash == prev`, then set
   `prev = hash`.
6. For every full non-redacted entry, recompute the content hash per §1.5 and
   require it to match. Require `redactionCount` to equal the number of
   entries carrying `redacted: true` (§2.3 — stubs do not count).
6c. If any process-context field (§2.6) is present, require it to be
   well-formed, and require `startTimestamp` / `endTimestamp` to equal the
   `ts` of the first and last non-stub entries. Failure codes:
   `processContext`, `timestamps`.
7. Report: signature validity, key id (with the out-of-band trust note),
   digest match, linkage result, counts of recomputed / redacted / stub
   entries. Redacted and stub entries MUST be visibly reported, not silently
   passed.

8. If `timestamp` is present (§2.5), report it: the declared TSA and message
   imprint, plus whatever informative checks were performed — clearly labeled
   as **not** a cryptographic verification of the token unless the verifier
   actually validates the token's CMS structure and the TSA certificate chain.

A packet is *valid* when steps 1–6 (including 6c) pass. What validity means
— and does not mean — is spelled out in §3.

The CLI and browser implement the Testigo profile. The reference verifier
defaults to Testigo and additionally implements an **explicitly selected**
session-chain draft profile (`--profile session-chain`); see
[`predicate/session-chain.md`](predicate/session-chain.md). Its RFC 3339
`exportedAt`, optional project/generator, required redaction count, and
artifact/evidence rules MUST NOT be imposed on Testigo packets or silently
used to accept them as draft packets.

A [conformance suite](conformance/) provides golden vectors isolating each
step above (and §2.5), plus a reference verifier to run them.

### 2.5 Trusted timestamp (optional, additive)

A producer MAY obtain an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)
timestamp on the packet's signature at export time and embed it as a top-level
member of the packet:

```json
"timestamp": {
  "type": "rfc3161",
  "tsaUrl": "https://freetsa.org/tsr",
  "hashAlg": "sha256",
  "messageImprint": "<lowercase hex sha256 of the raw signature bytes>",
  "token": "<base64(DER TimeStampResp, exactly as returned by the TSA)>"
}
```

The message imprinted is sha256 over the **raw (base64-decoded) bytes of
`signatures[0].sig`**. Timestamping the signature — rather than the payload —
proves the *signing act*, and therefore everything signed, existed no later
than the token's `genTime` (the CAdES signature-time-stamp construction).

`tsaUrl`, `hashAlg` and `messageImprint` are convenience copies; the
authoritative imprint is the one inside the token. `token` carries the DER
`TimeStampResp` unmodified, so standard tooling consumes it directly.

Because the timestamp lives outside the signed envelope, stripping it does not
break the signature — removal loses the existence proof but forges nothing.
Verifiers MUST treat its absence as normal, never as a failure. The field is
additive: `format` stays `testigo-proofpack/v0.1`, the predicate type does not
change, and packets with or without `timestamp` are equally valid.

**Verifying the token.** Full verification means validating the token's CMS
signature and the TSA's certificate chain, e.g.:

```
base64 -d ts-token.b64 > packet.tsr
openssl ts -reply -in packet.tsr -text                       # inspect
openssl ts -verify -digest <messageImprint> -in packet.tsr -CAfile <tsa-chain.pem>
```

A portable verifier that does not implement ASN.1/CMS MUST NOT claim to verify
the token. It SHOULD report the token's presence and MAY perform *informative*
checks: that sha256 of the signature bytes equals `messageImprint`, and that
those digest bytes occur inside the token DER. Trust in the timestamp is trust
in the chosen TSA.

**Privacy note:** requesting a token reveals to the TSA (and to network
observers) only a signature hash and the requester's network origin — no
ledger content.

### 2.6 Process context (optional, additive — v0.2)

The predicate MAY carry five more members, placed before `events`:

```json
"provider": {
  "harness": { "name": "testigo-cli", "version": "0.2.0" },
  "agent": { "id": "claude-code", "name": "Claude Code" },
  "languageModels": [ { "resolved": "claude-opus-4-8" }, { "inferenceProvider": "anthropic/claude-opus-4-8" } ]
},
"contextArtifacts": [
  { "tags": ["instructions"], "uri": "CLAUDE.md", "digest": { "sha256": "<hex>" } }
],
"startTimestamp": "2026-07-15T16:41:19.508Z",
"endTimestamp":   "2026-07-15T16:42:15.987Z",
"owner": "login-or-email"
```

They answer the questions a process-level consumer asks of a session log —
which harness, agent and models; which instructions; when; who is
accountable — and they take their shapes from the *Agentic Process
Evidence* proposal (`Provider`, `ContextArtifact`, `owner`,
`startTimestamp` / `endTimestamp`) so a packet slots into an APE
`sessionsLogs[]` reference without translation.

Rules:

- **All five are optional.** Absence is never a failure. Presence MUST be
  well-formed: `provider` is an object whose `harness` has non-empty `name`
  and `version`; `agent`, when present, is an object; `languageModels`,
  when present, is an array of objects. Each `contextArtifacts` entry has
  **exactly one** of `uri` / `data`, an optional `digest` whose `sha256` is
  lowercase hex, and optional `tags` (non-empty strings). `owner`, when
  present, is a non-empty string. Violations fail verification with code
  `processContext`.
- **The window is checkable, so it MUST be checked.** `startTimestamp` and
  `endTimestamp` come together or not at all; both are RFC 3339 with a `Z`
  designator; and they MUST equal the `ts` of the first and of the last
  **non-stub** entry in `events` (redaction preserves `ts`, so the check
  holds across redacted lines). Failure code: `timestamps`.
- **Derived, not typed.** Producers SHOULD derive `provider.languageModels`
  from `session_start` / `model_switch` events of the sessions involved
  (which MAY sit outside the exported range — a model is a session
  property), and `contextArtifacts` from the `context` members of the
  `prompt` events *inside* the segment. A redacted prompt contributes
  nothing: the derivation MUST NOT invent what the packet no longer shows.
- **Vantage, as everywhere.** `provider`, `contextArtifacts` and `owner`
  are producer assertions. A verifier checks their shape and, for the
  window, their consistency with the hashed lines; it does not establish
  that the named model ran or that the named human is accountable. The
  signer's key id remains the accountability anchor; `owner` is a label
  for the humans reading the packet (and for APE's `owner` field).

The additive rule of §5 applies: verifiers that predate v0.2 ignore these
members; the chain, digest and signature checks are unchanged.

---

## 3. Security considerations

**What a valid packet proves:** the holder of the signing key exported this
exact segment; the segment is internally consistent (linkage + content hashes
of shared events); it has not been modified since export.

**What it does not prove:**

- That the ledger is *complete* (events could have been withheld from capture,
  or the whole ledger fabricated before signing — the local ledger is
  tamper-evident only against post-hoc edits).
- That per-event timestamps are accurate (`ts` is the producer's local clock).
  A packet-level RFC 3161 token (§2.5) anchors the *export* in time — trust
  then rests on the chosen TSA — but does not correct per-event timestamps.
- That the event→turn binding is exact (§1.3 — heuristic, declared).
- The content of redacted events (declared unverifiable, by design).
- Who physically operated the machine — `actor: human` records that the
  producing software attributed the action to its human operator.

Verifiers and downstream consumers MUST NOT overstate these claims.

**Key management:** the reference implementation generates the Ed25519 key
into the OS keychain on first export. Key rotation invalidates nothing (old
packets verify with the old key); publishers SHOULD communicate current key
ids over a channel receivers already trust.

## 4. Compliance mapping (informative)

- **EU AI Act, art. 12** (record-keeping / decision reconstruction): the
  ledger records input context (prompt), the executing system (engine,
  session), the action (tool + input), and the result (tool results, diff) —
  per decision, replayable.
- **EU AI Act, art. 14** (human oversight): `approval_request` /
  `approval_decision` pairs record what was asked, what a human decided, and
  the stated reason, durably.
- ISO/IEC 42001 and SOC 2 change-management controls map naturally onto
  packets attached to changes.
- **FINOS AI Governance Framework, Agentic Process Evidence** (issue #384):
  a packet is a session log with integrity and signature of its own;
  §2.6 carries the provider, context, window and owner fields APE asks of
  one. Field-by-field mapping in [docs/ape-mapping.md](docs/ape-mapping.md).

This mapping is informative, not legal advice.

## 5. Versioning

The predicate type URI carries the version
(`https://github.com/cyl-castillo/testigo/attestation/v0.1`). Breaking changes bump the version;
verifiers MUST reject predicate types they don't implement. Ledger-level additions (new kinds, new payload fields — §1.7) and
predicate-level optional members (§2.6) are non-breaking: verifiers MUST
ignore unknown predicate fields and unknown kinds. v0.2 is such an addition
and keeps the v0.1 type URI.

### Verification changes

The profile and structural checks in §2.3.1–§2.4 are **verifier-side
tightenings**, not additive format changes under this section. Previously
accepted signed packets with a wrong statement type, missing required fields,
empty events, inconsistent ranges/sequences, or extra entry-wrapper keys now
fail verification. Packets produced by the reference implementation and the
CLI are unaffected. Serialization and predicate URIs are unchanged, so no
format or predicate version bump is required; allowed additive fields and
unknown event kinds remain valid.

The new `firstFailure` codes are `payloadType`, `statementType`, `predicate`,
`subject`, `events`, `entry`, `range`, and `sequence`. The reference API also
adds `profile` for an unsupported caller-selected profile. The existing
`predicateType` check now applies in default Testigo verification (including
the CLI); selecting the session-chain draft always enforces its existing
`exportedAt` check, including calendar validity. Existing `redactionCount`
and `processContext` codes cover the corresponding structural tightenings.

The browser's RFC 3161 handling is a **loosening**: an undecodable token or
an imprint mismatch is now a warning rather than a packet failure, matching
the CLI and reference verifier's informative timestamp handling (§2.5).
This does not establish CMS signature validity or TSA trust; the timestamp
is not cryptographically verified by these checks.
