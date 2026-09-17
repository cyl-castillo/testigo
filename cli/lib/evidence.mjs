// External evidence (SPEC §1.7, `external_evidence`): commit the chain to the
// bytes of a record that lives somewhere else — a Claude Code transcript, an
// export from Anthropic's Compliance API, a GitHub agent session log, any
// file or URL. The ledger stores where it was and the sha256 of what the
// producer saw; it never stores the bytes. A receiver who obtains the same
// record from the platform recomputes the digest and knows it is the one
// this session committed to. Vantage, said plainly: the digest binds the
// bytes at the moment of capture, not the record's later history.

import crypto from "node:crypto";
import fs from "node:fs";

import { append, caseFor, readLedger, readState } from "./ledger.mjs";

export const SOURCES = ["claude-code-transcript", "anthropic-compliance-api", "github-agent-logs", "file", "url"];

const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

/// Digest a local file or an http(s) URL. URLs are fetched once, as-is
/// (bring cookies or tokens yourself via a downloaded file when the log
/// sits behind a login — GitHub's agent session pages do).
export async function digestTarget(target) {
  if (/^https?:\/\//i.test(target)) {
    const res = await fetch(target, { redirect: "follow" });
    if (!res.ok) throw new Error(`fetch ${target}: HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    return { uri: target, sha256: sha256hex(buf), bytes: buf.length, mediaType: res.headers.get("content-type")?.split(";")[0] || undefined };
  }
  const buf = fs.readFileSync(target);
  return { uri: target, sha256: sha256hex(buf), bytes: buf.length };
}

/// Append an `external_evidence` event bound to the case of `termId` (or
/// the most recently active session). `source` names the system the record
/// comes from; `note` is free text (what the record is, for a human).
export async function attachEvidence(root, { target, source = "file", note, termId, turnId }) {
  if (!SOURCES.includes(source)) throw new Error(`unknown source "${source}" (one of: ${SOURCES.join(", ")})`);
  const d = await digestTarget(target);
  let term = termId;
  if (!term) {
    const sessions = Object.entries(readState(root).sessions ?? {}).sort((a, b) => (b[1].lastTs ?? 0) - (a[1].lastTs ?? 0));
    term = sessions[0]?.[0];
    if (!term) {
      const { parsed } = readLedger(root);
      term = parsed.at(-1)?.termId;
    }
  }
  const caseId = term ? caseFor(root, term) : "unbound";
  return append(root, {
    caseId,
    ...(turnId ? { turnId } : {}),
    kind: "external_evidence",
    ...(term ? { termId: term, sessionId: term } : {}),
    actor: "system",
    payload: { source, uri: d.uri, sha256: d.sha256, bytes: d.bytes, ...(d.mediaType ? { mediaType: d.mediaType } : {}), ...(note ? { note } : {}) },
  });
}
