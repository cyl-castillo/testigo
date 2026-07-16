# Testigo protocol — v0.1 (draft)

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
- **Stub** — `{ "stub": { "seq", "prevHash", "hash", "kind" } }` — an event
  inside the exported range that belongs to another case. Stubs preserve chain
  linkage while sharing nothing else (Merkle-style pruning).

`range.prevHashBefore` is the `hash` of the event immediately before
`fromSeq` (`"genesis"` when `fromSeq` is 0), anchoring the segment's start.
`ledgerHead` reports the producing ledger's tail at export time (informative).

Producers MUST refuse to export a ledger whose chain does not verify.

### 2.4 Verification algorithm

Given a packet, a verifier MUST:

1. Check `format`.
2. Decode `publicKey`; compute `keyid` = sha256 hex; require it to equal
   `signatures[0].keyid`.
3. Verify the Ed25519 signature over `PAE(payloadType, payload)`.
4. Parse the statement; recompute the subject digest over the compact
   serialization of `predicate.events`; require equality.
5. Walk `events` in order, starting `prev = range.prevHashBefore`. For every
   entry (full, redacted, or stub): require `prevHash == prev`, then set
   `prev = hash`.
6. For every full non-redacted entry, recompute the content hash per §1.5 and
   require it to match.
7. Report: signature validity, key id (with the out-of-band trust note),
   digest match, linkage result, counts of recomputed / redacted / stub
   entries. Redacted and stub entries MUST be visibly reported, not silently
   passed.

8. If `timestamp` is present (§2.5), report it: the declared TSA and message
   imprint, plus whatever informative checks were performed — clearly labeled
   as **not** a cryptographic verification of the token unless the verifier
   actually validates the token's CMS structure and the TSA certificate chain.

A packet is *valid* when steps 1–6 pass. What validity means — and does not
mean — is spelled out in §3.

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

This mapping is informative, not legal advice.

## 5. Versioning

The predicate type URI carries the version
(`https://github.com/cyl-castillo/testigo/attestation/v0.1`). Breaking changes bump the version;
verifiers MUST reject predicate types they don't implement. Ledger-level
additions (new kinds, new payload fields) are non-breaking (§1.6).
