#!/usr/bin/env node
// Re-homes the session-chain vector manifest into the per-predicate
// conformance layout proposed for the in-toto attestation repository in
// in-toto/attestation#597 (one `conformance/<predicate>/manifest.json` per
// predicate; each entry declares the verdict a conforming verifier must
// reach, and a declared comparison surface says which fields count).
//
// manifest.json stays the source of truth: the runner (../../conformance/
// verify.mjs --profile session-chain) reads it, and this script derives the
// #597-shaped file from it. Nothing here is a second normative surface.
//
// Usage:
//   node intoto-manifest.mjs           # rewrite intoto-manifest.json
//   node intoto-manifest.mjs --check   # exit 1 if the committed file is stale

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(here, "manifest.json");
const target = path.join(here, "intoto-manifest.json");

// Failure code → the rule in predicate/session-chain.md it exercises. The
// ids name sections of the draft so a divergence names a sentence, not a
// file. `parsing-rules` covers the structural profile; `verification-N` is
// step N of the Verification paragraph.
const CONDITIONS = {
  payloadType: ["parsing-rules"],
  statementType: ["parsing-rules"],
  predicate: ["parsing-rules"],
  events: ["parsing-rules"],
  range: ["parsing-rules"],
  sequence: ["parsing-rules"],
  entry: ["parsing-rules"],
  subject: ["parsing-rules", "verification-2"],
  predicateType: ["verification-0"],
  exportedAt: ["verification-0"],
  signature: ["verification-1"],
  digest: ["verification-2"],
  linkage: ["verification-3"],
  contentHash: ["verification-4"],
  redactionCount: ["verification-4"],
  processContext: ["verification-6"],
  timestamps: ["verification-6"],
};
const ACCEPT_PATH = ["verification-0", "verification-1", "verification-2",
  "verification-3", "verification-4", "verification-5"];

function build() {
  const m = JSON.parse(fs.readFileSync(source, "utf8"));
  const vectors = m.vectors.map((v) => {
    const id = v.file.replace(/\.proofpack\.json$/, "");
    const file = `statements/${v.file}`;
    if (v.expect.valid) {
      const expected = { verdict: "valid" };
      if (v.expect.counts) expected.counts = v.expect.counts;
      if (v.expect.timestamp !== undefined) expected.timestamp = v.expect.timestamp;
      const conditions = [...ACCEPT_PATH];
      if (v.expect.timestamp && v.expect.timestamp !== "none") conditions.push("timestamp-declared");
      if (v.expect.counts && (v.expect.counts.redacted || v.expect.counts.stubs)) conditions.push("entry-forms");
      return { id, kind: "accept", file, conditions, expected, description: v.description };
    }
    const code = v.expect.firstFailure;
    if (!CONDITIONS[code]) throw new Error(`unmapped failure code ${code} in ${v.file}`);
    return {
      id, kind: "reject", file, conditions: CONDITIONS[code],
      expected: { verdict: "invalid", codes: [code] }, description: v.description,
    };
  });
  const counts = {
    accept: vectors.filter((v) => v.kind === "accept").length,
    reject: vectors.filter((v) => v.kind === "reject").length,
  };
  return {
    $comment: "Derived from manifest.json by intoto-manifest.mjs in the per-predicate layout of in-toto/attestation#597. `file` paths assume the statements are re-homed under statements/; here they live beside manifest.json.",
    predicateType: m.enforce.predicateType,
    specPath: "predicate/session-chain.md",
    keyId: m.keyId,
    comparisonSurface: {
      normative: ["verdict"],
      measured: ["codes", "counts", "timestamp"],
      note: "An independent reader conforms when its accept/reject verdict matches every entry. The code on a reject entry is the step the vector was cut to isolate (everything before it passes), and the reference verifier is pinned to it; the draft requires rejection without ranking the structural checks, so a reader reaching the same verdict through a different check is in agreement and the differing code is a reason-parity datum to report, not a failure. Counts and the timestamp status are what a verifier must report visibly (redacted and stub entries, declared-not-verified RFC 3161 tokens), measured for the same reason.",
    },
    counts,
    vectors,
  };
}

const text = JSON.stringify(build(), null, 2) + "\n";
if (process.argv.includes("--check")) {
  // Compare with CRLF normalized: a Windows checkout with autocrlf rewrites
  // the committed file's line endings without changing its content.
  const current = fs.existsSync(target) ? fs.readFileSync(target, "utf8").replace(/\r\n/g, "\n") : "";
  if (current !== text) {
    console.error(`${path.relative(process.cwd(), target)} is stale: run node ${path.relative(process.cwd(), fileURLToPath(import.meta.url))}`);
    process.exit(1);
  }
  console.log(`intoto-manifest.json is current (${JSON.parse(text).vectors.length} vectors)`);
} else {
  fs.writeFileSync(target, text);
  console.log(`wrote ${path.relative(process.cwd(), target)}`);
}
