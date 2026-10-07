// Proof-packet export (SPEC.md §2): select segment → redact → pack (stubs
// for out-of-case events) → sign as DSSE → optional RFC 3161 timestamp.
//
// Key storage, honestly: an 0600 file under ~/.config/testigo — not an OS
// keychain (the reference implementation uses one; a zero-dependency CLI
// cannot). Anyone who can read that file can sign as you; treat it like an
// SSH key. The trust anchor for receivers is unchanged either way: the key
// id, compared out-of-band.

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { readLedger, sha256hex, verifyChain } from "./ledger.mjs";
import * as rfc3161 from "./rfc3161.mjs";
import { verifyPacket } from "./verify.mjs";

const CLI_VERSION = "0.2.0";
const FORMAT = "testigo-proofpack/v0.1";
const PREDICATE_TYPE = "https://github.com/cyl-castillo/testigo/attestation/v0.1";
const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const HOSTED_VERIFIER = "https://cyl-castillo.github.io/testigo/verifier/testigo-verifier.html";

export function keyFile() {
  const base =
    process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim() !== ""
      ? process.env.XDG_CONFIG_HOME
      : path.join(os.homedir(), ".config");
  return path.join(base, "testigo", "signing.key");
}

function loadOrCreateSeed() {
  const p = keyFile();
  if (fs.existsSync(p)) {
    const seed = Buffer.from(fs.readFileSync(p, "utf8").trim(), "base64");
    if (seed.length !== 32) throw new Error(`${p} is not a base64 32-byte seed`);
    return seed;
  }
  const seed = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  fs.writeFileSync(p, seed.toString("base64") + "\n", { mode: 0o600 });
  return seed;
}

function keys(seed) {
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const pubRaw = crypto.createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32);
  return { priv, pubRaw, keyId: sha256hex(pubRaw) };
}

export function keyInfo() {
  const { pubRaw, keyId } = keys(loadOrCreateSeed());
  return { keyId, publicKey: pubRaw.toString("base64"), file: keyFile() };
}

// Same conservative token-shaped patterns as the reference implementation:
// quote-safe on purpose — an eager regex that ate a JSON quote would corrupt
// the line.
const PATTERNS = [
  // Home directories: prompts record their cwd and evidence records their
  // path; a packet that leaves the machine should not name the operator.
  [/\/home\/[A-Za-z0-9._-]+/g, "[REDACTED:home]"],
  [/\/Users\/[A-Za-z0-9._-]+/g, "[REDACTED:home]"],
  [/AKIA[0-9A-Z]{16}/g, "[REDACTED:aws-key]"],
  [/ghp_[A-Za-z0-9]{36,}/g, "[REDACTED:github-token]"],
  [/github_pat_[A-Za-z0-9_]{22,}/g, "[REDACTED:github-token]"],
  [/xox[baprs]-[A-Za-z0-9-]{10,}/g, "[REDACTED:slack-token]"],
  [/sk-[A-Za-z0-9_-]{20,}/g, "[REDACTED:api-key]"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]*-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED:private-key]"],
  [/[Bb]earer [A-Za-z0-9._~+/-]{20,}/g, "[REDACTED:bearer]"],
];

function autoRedact(line) {
  let out = line;
  let count = 0;
  for (const [re, repl] of PATTERNS) {
    const hits = out.match(re);
    if (hits) {
      count += hits.length;
      out = out.replace(re, repl);
    }
  }
  return [out, count];
}

/// Manual redaction per §2.3: payload replaced, every other field — above
/// all prevHash/hash — kept, so linkage stays verifiable.
function manualRedact(line) {
  const v = JSON.parse(line);
  const fields = { ...v, payload: { redacted: "manual" } };
  const hash = fields.hash;
  delete fields.hash;
  return JSON.stringify({ ...fields, hash });
}

function readVerifiedLedger(root) {
  const snapshot = readLedger(root);
  const report = verifyChain(root, snapshot);
  if (!report.ok) throw new Error(`ledger chain broken at seq ${report.brokenAtSeq} — refusing to export`);
  return snapshot;
}

/// Final entries after automatic and requested redactions. The complete
/// statement (including metadata) is available through prepareStatement.
export function preview(root, caseId, { redactSeqs = [] } = {}) {
  return selectEntries(readVerifiedLedger(root), caseId, redactSeqs);
}

function redactLine(raw, seq, redactSeqs) {
  const [automatic, hits] = autoRedact(raw);
  const manual = redactSeqs.includes(seq);
  return { line: manual ? manualRedact(automatic) : automatic, autoRedacted: hits > 0, redacted: hits > 0 || manual };
}

function selectEntries({ lines, parsed }, caseId, redactSeqs) {
  if (!lines.length) throw new Error("ledger is empty — nothing to export");
  const inCase = (v) => caseId == null || v.caseId === caseId;
  const first = parsed.findIndex(inCase);
  const last = parsed.findLastIndex(inCase);
  if (first === -1) throw new Error(`case ${caseId} has no events in this ledger`);
  const entries = [];
  for (let i = first; i <= last; i++) {
    const v = parsed[i];
    if (inCase(v)) {
      entries.push({ seq: v.seq, kind: v.kind, actor: v.actor, stub: false, ...redactLine(lines[i], v.seq, redactSeqs) });
    } else {
      entries.push({ seq: v.seq, kind: v.kind, stub: true, prevHash: v.prevHash, hash: v.hash });
    }
  }
  const prevHashBefore = first > 0 ? parsed[first - 1].hash : "genesis";
  const head = parsed[parsed.length - 1];
  return { entries, range: { fromSeq: first, toSeq: last, prevHashBefore }, head: { seq: head.seq, hash: head.hash } };
}

/// `git config user.email` of the project, if any — the default `owner`
/// (§2.6). A producer assertion, like everything at predicate level.
function gitEmail(root) {
  try {
    const out = execFileSync("git", ["-C", root, "config", "user.email"], { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
    return out || null;
  } catch {
    return null;
  }
}

/// §2.6 process context, DERIVED from the hashed lines the packet carries —
/// never typed in at export. `owner` and `model` are the two producer
/// assertions a human may add on top (declared, not evidenced).
export function processContext(parsed, packed, { owner = null, model = null } = {}) {
  // Only what the packet SHOWS: packed lines after redaction. A manually
  // redacted prompt has no context left, and none is invented for it.
  const inCase = packed.filter((e) => typeof e.line === "string").map((e) => JSON.parse(e.line));
  const sessions = new Set(inCase.map((v) => v.sessionId).filter(Boolean));
  const models = [];
  const seenModel = new Set();
  const pushModel = (m) => {
    if (typeof m === "string" && m && !seenModel.has(m)) {
      seenModel.add(m);
      models.push({ resolved: m });
    }
  };
  // Model facts are session properties: session_start / model_switch events
  // of the involved sessions count even when they sit outside the segment.
  for (const v of parsed) {
    if (!sessions.has(v.sessionId)) continue;
    if (v.kind === "session_start") pushModel(v.payload?.model);
    if (v.kind === "model_switch") pushModel(v.payload?.to);
  }
  const languageModels = [...(model ? [{ inferenceProvider: model }] : []), ...models];
  const provider = {
    harness: { name: "testigo-cli", version: CLI_VERSION },
    agent: { id: "claude-code", name: "Claude Code" },
    ...(languageModels.length ? { languageModels } : {}),
  };
  const seenCtx = new Set();
  const contextArtifacts = [];
  for (const v of inCase) {
    if (v.kind !== "prompt" || !Array.isArray(v.payload?.context)) continue;
    for (const c of v.payload.context) {
      if (typeof c?.uri !== "string" || !c.uri || !/^[0-9a-f]{64}$/.test(c.sha256 ?? "")) continue;
      const k = `${c.uri}\n${c.sha256}`;
      if (seenCtx.has(k)) continue;
      seenCtx.add(k);
      contextArtifacts.push({ tags: ["instructions"], uri: c.uri, digest: { sha256: c.sha256 } });
    }
  }
  return {
    provider,
    ...(contextArtifacts.length ? { contextArtifacts } : {}),
    startTimestamp: new Date(inCase[0].ts).toISOString(),
    endTimestamp: new Date(inCase.at(-1).ts).toISOString(),
    ...(owner ? { owner } : {}),
  };
}

/// Build the complete unsigned statement from one verified snapshot. Review
/// and direct export share this path, including redactions and metadata.
export function prepareStatement(root, { caseId = null, redactSeqs = [], owner = null, model = null } = {}) {
  const snapshot = readVerifiedLedger(root);
  const pv = selectEntries(snapshot, caseId, redactSeqs);
  const entries = pv.entries.map((e) => {
    if (e.stub) {
      return { stub: { seq: e.seq, prevHash: e.prevHash, hash: e.hash, kind: e.kind } };
    }
    return { line: e.line, redacted: e.redacted };
  });
  // Session model facts can come from outside the selected segment. Apply
  // the same redactions there so metadata cannot restore removed content.
  const contextLines = snapshot.lines.map((line, i) => JSON.parse(redactLine(line, snapshot.parsed[i].seq, redactSeqs).line));

  const eventsBody = JSON.stringify(entries);
  return {
    _type: STATEMENT_TYPE,
    subject: [{ name: caseId ?? "ledger", digest: { sha256: sha256hex(Buffer.from(eventsBody, "utf8")) } }],
    predicateType: PREDICATE_TYPE,
    predicate: {
      caseId,
      project: path.basename(path.resolve(root)),
      exportedAtMs: Date.now(),
      generator: `testigo-cli/${CLI_VERSION}`,
      range: pv.range,
      ledgerHead: pv.head,
      redactionCount: entries.filter((e) => e.redacted).length,
      ...processContext(contextLines, entries, { owner: owner ?? gitEmail(root), model }),
      events: entries,
    },
  };
}

export function writeReview(root, { outDir, ...options }) {
  const statement = prepareStatement(root, options);
  const payload = Buffer.from(JSON.stringify(statement, null, 2) + "\n", "utf8");
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  // A fresh file per review: regenerating with redactions never overwrites
  // an earlier review that the human may still be inspecting.
  const file = path.join(outDir, `review-${crypto.randomUUID()}.json`);
  fs.writeFileSync(file, payload, { flag: "wx", mode: 0o600 });
  return { path: file, statement };
}

/// Check provenance against one freshly verified ledger snapshot without
/// regenerating any reviewed bytes or metadata. Redacted content remains a
/// producer assertion; its original seq/prevHash/hash must still exist.
function requireReviewProvenance(root, statement) {
  const { lines, parsed } = readVerifiedLedger(root);
  const { events, range, ledgerHead, project, caseId } = statement.predicate;
  const fail = (reason) => {
    throw new Error(`review does not match current ledger (${reason}) — regenerate the pre-sign review`);
  };
  if (project !== path.basename(path.resolve(root))) fail("project");
  if (!Number.isSafeInteger(range?.fromSeq) || range.fromSeq < 0 ||
      !Number.isSafeInteger(range?.toSeq) || range.toSeq < range.fromSeq ||
      range.toSeq - range.fromSeq + 1 !== events.length) fail("range");
  for (const [i, entry] of events.entries()) {
    const seq = range.fromSeq + i;
    const raw = parsed[seq];
    const hasLine = typeof entry?.line === "string";
    const reviewed = hasLine ? JSON.parse(entry.line) : entry?.stub;
    if (!raw || reviewed?.seq !== seq || reviewed.hash !== raw.hash || reviewed.prevHash !== raw.prevHash) {
      fail(`linkage at seq ${seq}`);
    }
    if (hasLine !== (caseId === null || raw.caseId === caseId)) fail(`case selection at seq ${seq}`);
    if (hasLine && entry.redacted !== true && entry.line !== lines[seq]) fail(`content at seq ${seq}`);
    if (!hasLine && reviewed.kind !== raw.kind) fail(`stub kind at seq ${seq}`);
  }
  if (range.prevHashBefore !== parsed[range.fromSeq].prevHash) fail("range anchor");
  // The saved head can precede today's tail: appends are expected while
  // reviewing. It must still be present, including when outside the range.
  if (!Number.isSafeInteger(ledgerHead?.seq) || ledgerHead.seq < range.toSeq ||
      parsed[ledgerHead.seq]?.hash !== ledgerHead.hash) fail("snapshot head");
}

/// Sign saved review bytes only after checking their ledger provenance.
/// Do not regenerate the statement, git identity, or export time.
/// --yes without a review remains an explicit unattended export.
export async function exportPacket(root, { outDir, tsa = null, reviewFile = null, ...options }) {
  const payload = reviewFile
    ? fs.readFileSync(reviewFile)
    : Buffer.from(JSON.stringify(prepareStatement(root, options)), "utf8");
  const statement = JSON.parse(payload.toString("utf8"));
  if (statement?._type !== STATEMENT_TYPE || statement.predicateType !== PREDICATE_TYPE ||
      !Array.isArray(statement.predicate?.events) || !statement.predicate.events.length ||
      !(statement.predicate.caseId === null || typeof statement.predicate.caseId === "string")) {
    throw new Error("invalid review statement — regenerate the pre-sign review");
  }
  if (reviewFile) requireReviewProvenance(root, statement);
  const { caseId, events: entries, redactionCount } = statement.predicate;
  const { priv, pubRaw, keyId } = keys(loadOrCreateSeed());
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${PAYLOAD_TYPE.length} ${PAYLOAD_TYPE} ${payload.length} `, "utf8"),
    payload,
  ]);
  const sig = crypto.sign(null, pae, priv);

  const packet = {
    format: FORMAT,
    envelope: {
      payloadType: PAYLOAD_TYPE,
      payload: payload.toString("base64"),
      signatures: [{ keyid: keyId, sig: sig.toString("base64") }],
    },
    publicKey: pubRaw.toString("base64"),
  };
  const report = verifyPacket(packet);
  if (!report.valid) throw new Error(`invalid review statement (${report.firstFailure}) — regenerate the pre-sign review`);
  if (tsa) packet.timestamp = await rfc3161.obtain(tsa, sig);

  fs.mkdirSync(outDir, { recursive: true });
  const stem = caseId ? caseId.replace(/[:/\\]/g, "-") : "ledger";
  const file = path.join(outDir, `${stem}.proofpack.json`);
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(packet, null, 2) + "\n");
  fs.renameSync(tmp, file);

  // Ship the standalone verifier alongside when we can find it (repo
  // checkout / packaged copy); otherwise point at the hosted one.
  let verifier = HOSTED_VERIFIER;
  const local = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "verifier", "testigo-verifier.html");
  const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "verifier", "testigo-verifier.html");
  for (const src of [local, repo]) {
    if (fs.existsSync(src)) {
      verifier = path.join(outDir, "testigo-verifier.html");
      fs.copyFileSync(src, verifier);
      break;
    }
  }
  return {
    path: file,
    verifier,
    keyId,
    events: entries.filter((e) => e.line).length,
    stubs: entries.filter((e) => e.stub).length,
    redactions: redactionCount,
    timestamped: !!tsa,
  };
}
