# Testigo conformance suite

Golden test vectors for implementers of the Testigo proof-packet format
([SPEC.md](../SPEC.md) §2.4/§2.5). If your verifier reaches the same verdict
as [`vectors/manifest.json`](vectors/manifest.json) on every packet in
[`vectors/`](vectors/), it implements the verification algorithm correctly.

## The vectors

Each vector isolates **one** verification step: everything before the
targeted check passes, the targeted check fails (or, for `valid-*`,
everything passes). Three of them are *producer bugs signed over* —
`invalid-digest`, `invalid-linkage`, `invalid-content-hash` carry a **valid
signature** around an internal defect, because that is exactly the laundering
a verifier must catch instead of stopping at "signature OK".

| vector | isolates | expected |
|---|---|---|
| `valid-minimal` | — | valid; 5/5 content hashes recompute |
| `valid-redacted-stub` | §2.3 redaction + stubs | valid; 2 redacted + 1 stub **visibly reported** |
| `valid-unknown-kind` | §1.7 open kinds | valid; unknown kinds MUST NOT fail verification |
| `invalid-format` | §2.4 step 1 | reject: unknown format |
| `invalid-keyid` | step 2 | reject: keyid ≠ sha256(publicKey) |
| `invalid-signature` | step 3 | reject: DSSE signature invalid |
| `invalid-digest` | step 4 | reject: subject digest ≠ packed events (signature valid!) |
| `invalid-linkage` | step 5 | reject: chain broken at a stub (signature + digest valid!) |
| `invalid-content-hash` | step 6 | reject: clean line doesn't recompute (linkage holds!) |
| `invalid-redaction-count` | §2.3 / step 6 | reject: `redactionCount` ≠ redacted entries — **stubs are not redactions** |
| `valid-timestamped` | §2.5 | valid; RFC 3161 token **declared** (real freetsa.org token) |
| `invalid-timestamp` | §2.5 | **valid** (steps 1–6 pass) — but the timestamp MUST be reported as not matching, never as proof |
| `valid-timestamp-stripped` † | §2.5 | valid, timestamp absent: stripping loses the existence proof but forges nothing |
| `invalid-timestamp-transplant` † | §2.5 | valid, timestamp MUST report mismatch: a token spliced from another packet must never migrate |

† donated by [@Rul1an](https://github.com/Rul1an) from the corpus cross in
[#1](https://github.com/cyl-castillo/testigo/issues/1) — surfaced by adversarial
mutation runs of an independently written checker (spec text only, 11/11
verdict parity with this suite on first run).

A **session-chain subset** ([`../predicate/vectors/`](../predicate/vectors/))
instantiates the same rules under the draft in-toto predicate conventions
(`in-toto.io/attestation/session-chain/v0.1` type URI, RFC 3339 `exportedAt`)
so checkers of that predicate have bytes to run against. `verify.mjs` runs
both sets.

`invalid-timestamp` encodes the subtlest rule: the timestamp lives outside
the signed envelope, so a bad one does not invalidate the packet — it
invalidates only the existence-in-time claim, and saying otherwise in either
direction is a conformance failure.

## Running

```
node verify.mjs                      # run the whole suite (exits non-zero on any mismatch)
node verify.mjs some.proofpack.json  # verify a single packet, print the verdict JSON
```

[`verify.mjs`](verify.mjs) is also a minimal **reference verifier** (~120
lines, Node ≥ 20, zero dependencies), written from the spec independently of
the generator. The suite passing means two independent code paths — this one
and the [browser verifier](../verifier/testigo-verifier.html) — agree on
every vector.

## The conformance key

Vectors are signed with a **published throwaway key**: Ed25519 seed
`0x42` × 32, key id
`3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f`
(recompute: sha256 of the raw public key). Anything signed with it proves
nothing and never will — it exists so the suite is reproducible:
`generate.mjs` is fully deterministic (fixed timestamps, deterministic
Ed25519, no randomness), so regenerating produces byte-identical vectors.

## Regenerating

```
node generate.mjs
```

The two timestamp vectors embed a real RFC 3161 token
(`fixtures/timestamp-token.b64`, one-time fetch from freetsa.org). Because
signatures are deterministic, the committed token stays valid until the
packet payload itself changes — if it does, `generate.mjs` fails loudly and
prints the exact commands to fetch a fresh token.
