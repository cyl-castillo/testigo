# Proof packet validation review

This change closes signed-packet validation gaps without changing packet
serialization, the format version, or either predicate URI. A valid signature
alone previously allowed unknown predicate types, wrong statement and payload
types, false ranges, non-contiguous sequences, and missing Testigo metadata.

## Profile decisions

| Check | Testigo (CLI, browser, default reference) | Explicit session-chain reference |
|---|---|---|
| Predicate URI | Testigo v0.1, exact | Draft session-chain v0.1, exact |
| DSSE / statement | `application/vnd.in-toto+json` / Statement v1 | Same |
| Project / generator | Required strings, as in the existing schema | Optional strings, as in the draft |
| Export time | Required integer `exportedAtMs` | Required calendar-valid UTC RFC 3339 `exportedAt` |
| Redaction count | Legacy omission defaults to zero | Required |
| Segment digest | First subject descriptor | Subjects, or evidence with artifact subjects |
| Range / sequences | Inclusive, nonempty, contiguous across every entry form | Same |

The reference API preserves the manifest's `enforce.predicateType` selection
mechanism, but accepts only the two implemented URIs. The draft time rule is
mandatory whenever that profile is selected; it cannot be disabled by omitting
the manifest's legacy `exportedAt` flag. There is no automatic profile selection
from signed packet data. CLI tests no longer waive the migration negatives.

In the draft, a subject named like the evidence descriptor repeats that segment
descriptor and must match its digest. Other artifact digests are producer
assertions, not recomputable from a ledger export. The reference now checks this
existing draft path as well as artifact-less subjects.

## Compatibility

- Unknown predicate, statement, ledger, stub and descriptor fields remain
  additive. Unknown event kinds remain valid; payload contents are informative.
  Entry wrappers retain the existing schema's closed `{line, redacted}` or
  `{stub}` alternatives. A string such as `"false"` is not a redaction boolean.
- `caseId` and `ledgerHead` remain optional; `ledgerHead` remains informative
  and may describe a later ledger tail. Empty project/generator strings retain
  their existing schema acceptance. Stub `kind` remains optional.
- Missing Testigo `redactionCount` retains the published schema/default behavior
  only when no entries are redacted. A missing count on redacted entries fails.
- Partial ranges, a single event, and all-stub segments are valid. Empty arrays
  cannot describe a nonempty inclusive range; the producer already refuses
  empty exports. Sequence integers must be exactly representable within the
  supplied verifiers' supported range; rounded numbers are not verified.
- Optional process context retains its existing rules. The artifact `uri`/`data`
  exclusivity check now tests presence, so an empty second field cannot bypass
  the schema's `oneOf`. A present artifact digest requires `sha256`, aligning
  the schema with SPEC §2.6 and the existing verifier behavior.
- Optional RFC 3161 timestamp mismatches remain informative. The browser now
  uses a warning, matching the reference and CLI verdicts; it does not verify
  CMS or TSA trust. Packet signatures and existing timestamp fixtures are
  unchanged.

The schema covers predicate structure, not profile identity, signatures,
decoded ledger lines, sequence equality, range length or other semantic checks.
Those checks run in the verifiers. All existing checked-in packets remain
byte-identical when the deterministic generator runs, apart from the manifests
which enumerate the new cases.

## Validation

Run from the repository root with Node 20 or later:

```text
node conformance/generate.mjs
node conformance/verify.mjs
node conformance/validation-test.mjs
node conformance/browser-test.mjs
node cli/test.mjs
node conformance/verify.mjs --profile session-chain predicate/vectors/sc-valid-minimal.proofpack.json
git diff --check
```

Results on Node 22.16.0 / Windows:

- Reference: 62 Testigo and 47 explicit session-chain vectors pass, including
  upstream's additive external-evidence vector.
- Independent cryptographic checks: all 68 new semantic-negative vectors have
  valid Ed25519 signatures; identity/range/sequence cases retain matching event
  digests and recomputable non-redacted content. Existing production/demo
  examples pass both Node verifiers. Profile-boundary and malformed-input
  assertions pass.
- Browser: all 109 vectors pass the Testigo verdict expectations using the
  HTML's actual script and WebCrypto with a minimal DOM. Redaction/stub warnings
  and timestamp mismatch warnings are asserted. This tests verification and
  rendering code, not browser-engine compatibility or visual layout.
- CLI: end-to-end capture, linking, torn-tail healing, export, redaction,
  process context and all corpus verdict assertions pass.
- Vector regeneration is deterministic; whitespace checks pass.

Test harness portability fixes use `fileURLToPath` for Windows and isolate git
identity lookup from the user's global configuration. No runtime dependencies
were added. The predicate schema was parsed and reviewed alongside the checks;
a standalone JSON Schema validator was not available in this environment.
The external Rust producer/verifier mentioned in repository prose is not in
this checkout and was not modified or tested.
