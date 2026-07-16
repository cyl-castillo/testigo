// Proof-packet export (SPEC.md §2): select segment → redact → pack (stubs
// for out-of-case events) → sign as DSSE → optional RFC 3161 timestamp.
//
// Key storage, honestly: an 0600 file under ~/.config/testigo — not an OS
// keychain (the reference implementation uses one; a zero-dependency CLI
// cannot). Anyone who can read that file can sign as you; treat it like an
// SSH key. The trust anchor for receivers is unchanged either way: the key
// id, compared out-of-band.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { readLedger, sha256hex, verifyChain } from "./ledger.mjs";
import * as rfc3161 from "./rfc3161.mjs";

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

/// The entries `export` would pack — the pre-sign review (§2.3, and the
/// reference implementation's F6 lesson: only a human can judge what a
/// pattern can't). Nothing is signed here.
export function preview(root, caseId) {
  const report = verifyChain(root);
  if (!report.ok) throw new Error(`ledger chain broken at seq ${report.brokenAtSeq} — refusing to export`);
  const { lines, parsed } = readLedger(root);
  if (!lines.length) throw new Error("ledger is empty — nothing to export");
  const inCase = (v) => caseId == null || v.caseId === caseId;
  const first = parsed.findIndex(inCase);
  const last = parsed.findLastIndex(inCase);
  if (first === -1) throw new Error(`case ${caseId} has no events in this ledger`);
  const entries = [];
  for (let i = first; i <= last; i++) {
    const v = parsed[i];
    if (inCase(v)) {
      const [line, hits] = autoRedact(lines[i]);
      entries.push({ seq: v.seq, kind: v.kind, actor: v.actor, stub: false, autoRedacted: hits > 0, line });
    } else {
      entries.push({ seq: v.seq, kind: v.kind, actor: v.actor, stub: true });
    }
  }
  const prevHashBefore = first > 0 ? parsed[first - 1].hash : "genesis";
  const head = parsed[parsed.length - 1];
  return { entries, range: { fromSeq: first, toSeq: last, prevHashBefore }, head: { seq: head.seq, hash: head.hash } };
}

/// Sign and write the packet. `redactSeqs` are the human's pre-sign marks.
export async function exportPacket(root, { caseId = null, outDir, redactSeqs = [], tsa = null }) {
  const pv = preview(root, caseId);
  const { parsed } = readLedger(root);
  let redactionCount = 0;
  const entries = pv.entries.map((e) => {
    if (e.stub) {
      const raw = parsed[e.seq];
      return { stub: { seq: raw.seq, prevHash: raw.prevHash, hash: raw.hash, kind: raw.kind } };
    }
    let line = e.line;
    let redacted = e.autoRedacted;
    if (e.autoRedacted) redactionCount++;
    if (redactSeqs.includes(e.seq)) {
      line = manualRedact(line);
      redacted = true;
      redactionCount++;
    }
    return { line, redacted };
  });

  const eventsBody = JSON.stringify(entries);
  const statement = {
    _type: STATEMENT_TYPE,
    subject: [{ name: caseId ?? "ledger", digest: { sha256: sha256hex(Buffer.from(eventsBody, "utf8")) } }],
    predicateType: PREDICATE_TYPE,
    predicate: {
      caseId,
      project: path.basename(path.resolve(root)),
      exportedAtMs: Date.now(),
      generator: "testigo-cli/0.1.0",
      range: pv.range,
      ledgerHead: pv.head,
      redactionCount,
      events: entries,
    },
  };
  const payload = Buffer.from(JSON.stringify(statement), "utf8");
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
  const local = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "verifier", "testigo-verifier.html");
  const repo = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "..", "verifier", "testigo-verifier.html");
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
