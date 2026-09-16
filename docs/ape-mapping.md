# Testigo ↔ Agentic Process Evidence (APE): field-by-field mapping

**Status:** draft for discussion, written for
[finos/ai-governance-framework#384](https://github.com/finos/ai-governance-framework/issues/384)
(JFrog, 2026-09-15) and the APE reference at
[jfrog/agentic-process-evidence](https://github.com/jfrog/agentic-process-evidence).
Testigo side: [SPEC.md](../SPEC.md) v0.2 and the in-toto
[session-chain predicate draft](../predicate/session-chain.md) from
[in-toto/attestation#554](https://github.com/in-toto/attestation/issues/554).

**Claim in one sentence:** APE and Testigo sit at different levels of the
same model and compose without either absorbing the other. APE's *process
evidence* is the statement bound to the SDLC subject (commit, artifact,
release); Testigo's *proof packet* is a tamper-evident, signed, selectively
disclosable *session log* that carries what APE's session log format does
not: human approval decisions with reasons, per-turn outcomes, and integrity
that a third party can verify without access to the log store.

---

## 1. Model alignment

| APE term | Meaning in APE | Testigo term | Notes |
|---|---|---|---|
| **Process** | The value unit the organisation is accountable for; aggregates every session that yielded one outcome; its outcome is the evidence subject | **Case** (`caseId`) | A case is an intent thread grouping turns across one or more sessions. Same idea, minus the "outcome = subject" rule, which the session-chain draft adopts (§ "Subject"). |
| **Session** | One agent run from the harness's point of view (`sessionId`) | **Session** (`sessionId`) + **Turn** (`turnId`) | Testigo subdivides a session into turns (prompt → stop). A turn is the unit that carries the working-tree diff. |
| **Session log** | JSON timeline of harness hook events, stored in a searchable store, referenced by `uri + digest` | **Ledger segment** exported as a **proof packet** | Same content class. Differences are in integrity, signing, disclosure and approval events (§4). |
| **Process evidence** | in-toto Statement on the SDLC subject | — (out of scope for Testigo) | Testigo does not aggregate sessions into a process statement. APE's job. |
| **Agent runtime tool** | Collects logs, extracts provenance, uploads logs + evidence on completion | **Producer** (agent-console, testigo-cli, Claude Code plugin) | Testigo producers capture locally and sign at export; they do not upload. An APE runtime tool can *consume* packets as its session logs. |
| **Alignment evidence** | Optional second statement with a policy verdict on a session log | — | Not in Testigo. A packet is a valid subject for it (content-addressed). |

```
APE process evidence  (subject = commit / artifact / release / session)
  └─ sessionsLogs[]  ──uri+digest──▶  Testigo proof packet  (DSSE-signed in-toto Statement)
                                        └─ predicate.events[]  = hash-chained ledger segment
                                             prompt → approval_request → approval_decision
                                             → tool_result → snapshot → turn_end (diff)
```

---

## 2. APE "an evidence MUST answer, at minimum" → Testigo

Legend: **covered** = present in the packet today · **derivable** = computable from packet events without new fields · **gap** = not carried by Testigo v0.1 · **APE-level** = belongs to the process statement, not the session log.

| # | APE requirement (issue #384) | Testigo v0.1 | Status | Notes / proposed v0.2 action |
|---|---|---|---|---|
| 1 | **Which agentic process operated** — agent, harness, models | `predicate.generator` (harness + version, e.g. `agent-console/0.48.1`), `sessionId` (engine conversation id), `actor` per event | **gap** (models) | Testigo records the harness but **not the language model(s)** and not a stable agent id. **Done in v0.2:** APE's `Provider` object verbatim as `predicate.provider`, with `languageModels` derived from the new `session_start` / `model_switch` ledger kinds. |
| 2 | **Which context resources** — guidelines, policies, prompts used | `prompt.payload.prompt`, `prompt.payload.skill`, `prompt.payload.cwd` | **partial** | The prompt itself is in the chain (byte-exact, hash-covered). Policies/guidelines read by the agent appear only as tool activity, not as digest-linked artifacts. **Done in v0.2:** `contextArtifacts[]` at predicate level, derived from the instruction-file digests each `prompt` event now records at capture time. |
| 3 | **Which agentic tools were involved** — skills, MCP tools, equivalents | `approval_request.payload.tool`, `tool_result.payload.tool`, `prompt.payload.skill` | **derivable** | The distinct set of `tool` values in the segment is APE's `tools[]`. Tool *versions* are not recorded (APE marks version optional). |
| 4 | **How to access the agentic session logs** | The packet **is** the log. `range`, `ledgerHead`, optional `evidence` ResourceDescriptor; hosted verifier | **covered** | Stronger than a URI: the referenced bytes carry their own integrity and signature, so access to the store is not a precondition for verification. |
| 5 | **Task details** — commit, Jira issue, released version, artifact | `caseId` (`jira:KEY`, `github:org/repo#N`), `snapshot.commitSha`, `turn_end.preSha/postSha`, `Testigo-Case:` / `Testigo-Head:` commit trailers | **covered** | Maps to APE `custom.requirements[].issue` (caseId) and `custom.baseCommit` (preSha). The subject rule in the session-chain draft puts produced artifacts in `subject`. |
| 6 | **Result of the agentic process** | `turn_end.payload.filesChanged[]`, `postSha`, `filesTruncated` | **covered at turn level**; `result` enum is **APE-level** | Testigo records *what changed*; APE records a process verdict (`COMPLETED`, `APPROVED`, …). Both are needed; neither replaces the other. |
| 7 | **Human accountable for the process** | DSSE signer (`keyid = sha256(pubkey)`, compared out-of-band); `actor: human` on `prompt` | **partial** | Testigo binds accountability to a signing key, APE to a login/email. **Done in v0.2:** optional `predicate.owner`; sigstore keyless (OIDC identity) stays on the roadmap as V2-C. Recommend APE allow a key identity alongside login/email. |
| 8 | **Humans that acted as reviewers or co-producers** | `approval_decision` events: `actor: human`, `decision: allow\|deny\|ask`, `reason`, bound to the `approvalId` of the request | **covered, stronger** | APE carries a *list of reviewers*; Testigo carries *each decision, its reason and its timestamp*, hash-chained between the request and the tool result. This is the per-action evidence Article 14 "meaningful oversight" needs — and the direct answer to the issue's "rubber stamp" challenge. |
| 9 | **Session start and end timestamps** | `ts` of the first `prompt` and the last `turn_end` (epoch ms, inside the hashed lines); `exportedAt` (RFC 3339) at predicate level | **derivable** | In-line `ts` cannot be rewritten to ISO 8601 without breaking the hashes. **Done in v0.2:** additive `startTimestamp` / `endTimestamp` (RFC 3339) at predicate level, computed from the events — and checked by verifiers against them. |

---

## 3. APE normative requirements → Testigo

| APE requirement | Testigo | Status |
|---|---|---|
| Evidence MUST be **signed** | DSSE envelope, ed25519; key id in the envelope, trust anchor compared out-of-band; optional RFC 3161 timestamp over the signature (§2.5) | **covered** |
| Evidence MUST be **immutable once written**, stored in a **tamper-evident system** that prevents retroactive modification | Hash chain over byte-exact lines (§1.5); optional git anchoring of the ledger head in refs and commit trailers (§1.6). Declared honestly as *tamper-evident, not tamper-proof* (§3). | **covered, with a stronger statement**: the integrity lives in the artifact, not only in the store. An auditor holding the packet needs no store. |
| Evidence MUST be **linked to the released software identity** for gating and post-market audit | Subject rule: produced artifacts (commit/tree from turn diffs) in `subject`; `Testigo-Case:` and `Testigo-Head:` trailers ride the commits into remote history | **covered** |
| Gates MUST verify evidence **exists**, is **signed**, and components were **approved under policy** (policy-as-code) | Existence + signature + chain: verifier, CLI, conformance suite. Component allow-listing needs the `Provider` object (gap #1). | **partial** → closed by adopting `Provider` |
| Session logs retained ≥ 6 months (EU AI Act art. 19) | Local ledger has no trim by design; retention policy is the deployer's | **deployer-level**, both specs |

---

## 4. Session log timeline ↔ Testigo event kinds

| APE `timeline[].event` | Testigo `kind` | Actor | Notes |
|---|---|---|---|
| `beforeSubmitPrompt` | `prompt` | human | Opens a turn. Testigo adds `skill` and `cwd`. |
| `preToolUse` | `approval_request` | agent | **Different meaning.** APE records that a tool is about to run; Testigo records that the agent *asked a human* (tool + bounded input). A pre-tool-use event without an approval gate is not an oversight event. |
| — (no equivalent) | `approval_decision` | human | `decision`, `reason`, `approvalId`. **The main thing APE's timeline lacks.** |
| `postToolUse` | `tool_result` | agent | Bounded excerpt + `truncated` flag. APE's optional `path_hashes` is a useful addition Testigo does not have. |
| `afterAgentResponse` | — | — | Testigo does not record assistant prose; it records actions and outcomes. Additive kind if wanted. |
| `sessionEnd` | `turn_end` | agent | Testigo closes a **turn**, not a session, and attaches `preSha`, `postSha`, `filesChanged[]`. |
| — | `snapshot` | system | Working-tree checkpoint (git sha) before the turn. |
| — | `case_link` | system | Binds a terminal to a case (ticket). |
| — | `job_run` | system | Scheduled/automated runs (no human prompt). |

Two structural differences beyond the kinds:

- **Integrity.** An APE session log is a JSON document whose integrity is the
  `digest` recorded in the process evidence. Re-serialisation anywhere in the
  pipeline changes the bytes without changing the meaning. Testigo lines are
  hashed byte-exact and chained, so the log carries its own integrity and the
  chain is verifiable independently of the process evidence (SPEC §1.5,
  deployment note).
- **Disclosure.** APE's example embeds `tool_input.contents` inline. Handing
  that log to an external auditor discloses everything. Testigo redacts per
  event with `seq`/`prevHash`/`hash` preserved, so linkage verifies while
  content is reported as unverifiable, never silently passed (SPEC §2.3). The
  published Fixy packet is exactly this: 7 of 12 entries redacted (the
  prompt's home path automatically, three agent requests and three tool
  results by hand), chain intact, approvals and empty diff fully verifiable.

---

## 5. What each side adds to the other

**Testigo adds to APE**

1. Per-action human approval decisions with reason, hash-chained between request and result (art. 14).
2. Tamper evidence *inside* the session log, not only at the store.
3. Third-party verification without store access: one HTML file, no network, no install.
4. Selective disclosure with verifiable linkage.
5. Per-turn outcome binding (pre/post tree, files changed).
6. A conformance corpus with signed negatives and two independently authored checkers in parity (the vetting bar set in in-toto/attestation#554).
7. RFC 3161 proof of existence over the signature.

**APE adds to Testigo (to adopt in v0.2, all additive)**

1. `Provider` (harness / agent / language models, requested and resolved).
2. `contextArtifacts[]` with tags and digests.
3. Process-level aggregation: many sessions → one subject; `traceId`.
4. `result` enum and `owner` / `reviewers` as logins or emails.
5. Searchable attributes for a store (`tools`, `agent`, `subject`, `sessionId`).
6. `path_hashes` on tool events.

---

## 6. Proposed changes to APE (concrete, small)

1. **`sessionsLogs[]` MAY reference a signed session-chain statement.** Keep
   `uri + digest`; add an optional `mediaType` (e.g.
   `application/vnd.in-toto+dsse`) or `predicateType` hint so a runtime tool
   or gate knows the referenced bytes are a DSSE envelope it can verify,
   rather than a plain timeline. No change for producers of plain logs.
2. **Add approval events to the timeline kinds:** `approvalRequested`
   (tool, bounded input, approvalId) and `approvalDecided` (approvalId,
   decision `allow|deny|ask`, reason, approver). Without them the standard
   cannot distinguish an agent that asked from one that did not, and
   "reviewers" stays a list rather than evidence. This helps APE even where
   Testigo is not used.
3. **Recommend session logs be tamper-evident in themselves** (hash-chained,
   byte-exact) and **redactable with linkage preserved**, so the
   "independent of any single harness or CI/CD system" goal in the issue's
   commentary holds for the log bytes, not only for the store.

## 7. Changes to Testigo (v0.2, additive, no predicate bump) — implemented

Shipped in SPEC v0.2 (§1.7, §2.6), the schema, the session-chain draft and
proto, the conformance corpus (`valid-process-context`,
`invalid-timestamp-window`, `invalid-process-context-shape`,
`sc-valid-process-context`), both Node verifiers, the browser verifier,
testigo-cli 0.2.0 and the agent-console reference implementation:

1. `predicate.provider` = APE `Provider`, with `languageModels` derived from
   the new `session_start` / `model_switch` ledger kinds.
2. `predicate.contextArtifacts[]` = APE `ContextArtifact`, derived from the
   instruction-file digests each `prompt` event now records at capture
   time (`payload.context`), so the claim rests on hashed evidence.
3. `predicate.startTimestamp` / `endTimestamp` (RFC 3339), which verifiers
   MUST check against the first/last non-stub entry's `ts`.
4. `predicate.owner` (login or email) alongside the signer key id; sigstore
   keyless (V2-C) remains the cryptographic version of the same fact.
5. Case id convention documented as compatible with `custom.requirements[].issue`.

The predicate type URI and packet format are unchanged: a v0.1 verifier
ignores the new members, a v0.2 verifier checks them when present.

---

## 8. Worked example, with real data

[`examples/ape/fixy-deploy-verification.ape-process-evidence.json`](../examples/ape/fixy-deploy-verification.ape-process-evidence.json)
is an APE process-evidence Statement whose **subject is the published Testigo
packet** of the Fixy production deploy verification (single-session process,
so per APE the subject is the session log itself):

| | |
|---|---|
| subject uri | `https://cyl-castillo.github.io/testigo/examples/fixy-deploy-verification.proofpack.json` |
| subject sha256 | `2c9d7f01ea070530b6bb25084d3e274a197c3e4d14508cb69281ab732145b23b` (the packet file bytes) |
| inner segment digest | `af21a0b7bfe48022764831415f1c82f45211f0b886ad59bbe4a19842308e0ceb` (Testigo subject) |
| signer key id | `8caf09075df11abbbdea5cd1d120a5654d8d1ce2a32e2a6f018dde557c5014da` |
| human approval decisions | 3 (`allow`, reason `approved once`), one per agent command |
| turn diff | `filesChanged: []`, pre `d272287…` → post `5523ec5…`: provably read-only |
| redaction | 7 of 12 entries redacted (the prompt's home path automatically, three agent requests and three tool results by hand), chain intact |

How to check it: download the packet, confirm its sha256 matches the APE
subject digest, then drop it on the
[hosted verifier](https://cyl-castillo.github.io/testigo/verifier/testigo-verifier.html).
The APE statement is generated from the packet by
[`examples/ape/build.mjs`](../examples/ape/build.mjs) — every field is derived
from the verified bytes — and is **unsigned** on purpose: it shows the shape,
it does not claim provenance for itself. This packet was captured before
v0.2, so its prompt carries no instruction digests and the predicate has no
`contextArtifacts`; sessions captured by a v0.2 producer carry them (§7).

---

## 9. Regulatory crosswalk (informative, not legal advice)

| Obligation | APE process evidence | Testigo packet |
|---|---|---|
| EU AI Act art. 12, record-keeping / decision reconstruction | Which systems, tools, context, result | Input (prompt), executing system, each action, each result, per decision, replayable |
| EU AI Act art. 14, human oversight | Owner, reviewers | Each approval request, decision and stated reason, durably |
| EU AI Act art. 19, log retention ≥ 6 months | Store retention | Ledger never trims; packets are files |
| EU AI Act art. 26, deployer monitoring | Searchable store, alignment evidence | Portable evidence a deployer can hand over without granting system access |
| Post-market monitoring (art. 72) | Locate sessions by commit / tool / model | Content-addressed segments cross-referenced by hash |

---

## 10. Open questions for the working group

1. Should APE define the session log as a *class* (any digest-linked, ordered
   event record) with the plain timeline and the signed session chain as two
   conforming shapes?
2. Naming: `approvalRequested` / `approvalDecided` in APE vs
   `approval_request` / `approval_decision` in Testigo (APE uses camelCase;
   Testigo lines are opaque bytes, so both can coexist).
3. Where should the shared predicate live: in-toto/attestation (#554 already
   hosts the session-chain draft and the agent-decision RFC) or the APE repo?
4. Identity: login/email (APE) vs signing key / OIDC identity (Testigo). Both,
   with a binding rule?
