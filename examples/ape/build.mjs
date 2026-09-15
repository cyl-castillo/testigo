#!/usr/bin/env node
// Build the APE (Agentic Process Evidence) process-evidence statement for a
// Testigo proof packet — the interoperability example in docs/ape-mapping.md
// §8. Reads the packet, verifies it with the conformance verifier, and emits
// an in-toto Statement whose SUBJECT is the packet itself (single-session
// process ⇒ the session log is the subject, per APE). Everything in the
// output is derived from the packet bytes; nothing is typed in except the
// hosted URL, the owner login and the intent line.
//
//   node examples/ape/build.mjs examples/fixy-deploy-verification.proofpack.json \
//     --url https://cyl-castillo.github.io/testigo/examples/fixy-deploy-verification.proofpack.json \
//     --owner cyl-castillo --intent "Verify the state of the Fixy production deploy (read-only)" \
//     > examples/ape/fixy-deploy-verification.ape-process-evidence.json
//
// The statement is UNSIGNED on purpose: it shows the shape, it does not claim
// provenance for itself.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { verifyPacket } from "../../conformance/verify.mjs";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
const opt = (n, d = null) => (args.includes(n) ? args[args.indexOf(n) + 1] : d);
if (!file) {
  console.error("usage: build.mjs <packet.proofpack.json> --url URL --owner LOGIN [--intent TEXT]");
  process.exit(1);
}
const bytes = fs.readFileSync(file);
const pkt = JSON.parse(bytes.toString("utf8"));
const v = verifyPacket(pkt);
if (!v.valid) {
  console.error(`refusing: packet does not verify (${v.firstFailure}) — fix the packet, not the example`);
  process.exit(1);
}
const st = JSON.parse(Buffer.from(pkt.envelope.payload, "base64").toString("utf8"));
const pred = st.predicate;
const lines = pred.events.filter((e) => typeof e.line === "string").map((e) => JSON.parse(e.line));
const iso = (ms) => new Date(ms).toISOString();
const [harnessName, harnessVersion] = String(pred.generator ?? "unknown/0").split("/");
const tools = [...new Set(lines.map((l) => l.payload?.tool).filter((t) => typeof t === "string" && t))];
const approvals = lines.filter((l) => l.kind === "approval_decision");
const turnEnds = lines.filter((l) => l.kind === "turn_end");
const last = turnEnds.at(-1)?.payload ?? {};
const snapshot = lines.find((l) => l.kind === "snapshot")?.payload?.commitSha;

const out = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ uri: opt("--url", `file:${path.basename(file)}`), digest: { sha256: crypto.createHash("sha256").update(bytes).digest("hex") } }],
  predicateType: "https://jfrog.com/evidence/agentic-dev-process/v1",
  predicate: {
    providers: [pred.provider ?? { harness: { name: harnessName, version: harnessVersion } }],
    traceId: pred.caseId ?? "ledger",
    ...(tools.length ? { tools: tools.map((name) => ({ name })) } : {}),
    ...(pred.contextArtifacts ? { contextArtifacts: pred.contextArtifacts } : {}),
    custom: {
      ...(snapshot ? { baseCommit: { digest: { gitCommit: snapshot } } } : {}),
      testigo: {
        packetFormat: pkt.format,
        predicateType: st.predicateType,
        signerKeyId: v.keyId,
        segmentDigest: st.subject[0].digest.sha256,
        ledgerHead: pred.ledgerHead,
        redactedEntries: v.counts.redacted,
        stubs: v.counts.stubs,
        humanApprovalDecisions: approvals.length,
        ...(turnEnds.length ? { turnDiff: { preSha: last.preSha, postSha: last.postSha, filesChanged: last.filesChanged ?? [] } } : {}),
        ...(pkt.timestamp ? { rfc3161: v.timestamp } : {}),
      },
    },
    result: "COMPLETED",
    ...(opt("--intent") ? { intents: [opt("--intent")] } : {}),
    processSummary:
      `${lines.length} witnessed events in case ${pred.caseId ?? "ledger"}: ` +
      `${approvals.length} human approval decision(s)` +
      `${approvals.length ? " (" + [...new Set(approvals.map((a) => a.payload?.decision))].join("/") + ")" : ""}, ` +
      `${v.counts.redacted} redacted entr${v.counts.redacted === 1 ? "y" : "ies"} with chain linkage intact, ` +
      `${turnEnds.length ? `turn diff ${(last.filesChanged ?? []).length} file(s)` : "no turn end"}. ` +
      `The packet referenced as subject is DSSE ed25519 signed by key ${v.keyId.slice(0, 8)}…; verify it at ` +
      `https://cyl-castillo.github.io/testigo/verifier/testigo-verifier.html.`,
    owner: opt("--owner", pred.owner ?? "unknown"),
    reviewers: approvals.length ? [opt("--owner", pred.owner ?? "unknown")] : [],
    startTimestamp: pred.startTimestamp ?? iso(lines[0].ts),
    endTimestamp: pred.endTimestamp ?? iso(lines.at(-1).ts),
  },
  createdAt: new Date().toISOString(),
  createdBy: "testigo examples/ape/build.mjs (derived from the packet; unsigned)",
};
process.stdout.write(JSON.stringify(out, null, 2) + "\n");
