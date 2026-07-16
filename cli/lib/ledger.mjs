// Ledger primitives (SPEC.md §1): per-project append-only JSONL with the
// hash chain, torn-tail healing, and an mkdir-based advisory lock — hooks
// fire concurrently (parallel tool calls), and two appends racing on the
// same tail would fork the chain.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MAX_PAYLOAD_BYTES = 4096;

export const sha256hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

export function dataDir() {
  const base =
    process.env.XDG_DATA_HOME && process.env.XDG_DATA_HOME.trim() !== ""
      ? process.env.XDG_DATA_HOME
      : path.join(os.homedir(), ".local", "share");
  return path.join(base, "testigo");
}

/// Stable per-project ledger key: readable slug + hash of the full root, so
/// two directories with the same basename never share a ledger.
export function ledgerKey(projectRoot) {
  const root = path.resolve(projectRoot);
  const slug = (path.basename(root) || "root")
    .replace(/[^a-zA-Z0-9]/g, "_")
    .slice(0, 24);
  return `${slug}-${sha256hex(Buffer.from(root, "utf8")).slice(0, 16)}`;
}

export const ledgerPath = (root) => path.join(dataDir(), "ledgers", `${ledgerKey(root)}.jsonl`);
export const statePath = (root) => path.join(dataDir(), "state", `${ledgerKey(root)}.json`);

/// mkdir is atomic on every platform — the classic zero-dep lock. Stale
/// locks (a crashed hook) are stolen after 10s so one bad exit can't wedge
/// witnessing forever.
export function withLock(target, fn) {
  const lock = `${target}.lock`;
  fs.mkdirSync(path.dirname(lock), { recursive: true });
  const deadline = Date.now() + 5000;
  for (;;) {
    try {
      fs.mkdirSync(lock);
      break;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > 10_000) {
          fs.rmdirSync(lock);
          continue;
        }
      } catch {
        continue; // lock vanished between check and stat — retry
      }
      if (Date.now() > deadline) throw new Error(`ledger lock stuck: ${lock}`);
      const until = Date.now() + 10;
      while (Date.now() < until); // hooks are short-lived; a 10ms spin beats a dependency
    }
  }
  try {
    return fn();
  } finally {
    try {
      fs.rmdirSync(lock);
    } catch {}
  }
}

/// Raw lines, byte-exact (hashes were computed over these bytes). A torn
/// final line (crash mid-append) is tolerated and reported; unparseable
/// lines anywhere else are tampering (§1.5).
export function readLedger(root) {
  const p = ledgerPath(root);
  if (!fs.existsSync(p)) return { lines: [], parsed: [], tornTail: false };
  const raw = fs.readFileSync(p, "utf8");
  const lines = raw.split("\n").filter((l) => l.trim() !== "");
  const parsed = [];
  let tornTail = false;
  for (let i = 0; i < lines.length; i++) {
    try {
      parsed.push(JSON.parse(lines[i]));
    } catch {
      if (i === lines.length - 1) {
        tornTail = true;
        lines.pop();
      } else {
        throw new Error(`unparseable ledger line at index ${i} — tampering or corruption`);
      }
    }
  }
  return { lines, parsed, tornTail };
}

/// Serialize with `hash` as the FINAL member over the exact bytes hashed
/// (§1.5): stringify with hash:"", sha256, then stringify with the digest.
function sealEvent(fields) {
  const unhashed = JSON.stringify({ ...fields, hash: "" });
  const hash = sha256hex(Buffer.from(unhashed, "utf8"));
  return JSON.stringify({ ...fields, hash });
}

/// Bound unbounded payload members (§1.7): tool inputs/outputs are truncated
/// to a marked preview so one Write call can't balloon the evidence file.
export function bounded(value) {
  const s = typeof value === "string" ? value : JSON.stringify(value ?? null);
  if (Buffer.byteLength(s, "utf8") <= MAX_PAYLOAD_BYTES) return { text: s, truncated: false };
  return { text: Buffer.from(s, "utf8").subarray(0, MAX_PAYLOAD_BYTES).toString("utf8"), truncated: true };
}

/// Append one event: lock → heal torn tail → chain from the real tail →
/// fsync. `spec` = {caseId, turnId?, kind, termId?, sessionId?, actor, payload}.
export function append(root, spec) {
  const p = ledgerPath(root);
  return withLock(p, () => {
    const { lines, tornTail } = readLedger(root);
    if (tornTail) {
      // Heal by rewriting without the torn line (atomic tmp+rename).
      const tmp = `${p}.tmp`;
      fs.writeFileSync(tmp, lines.length ? lines.join("\n") + "\n" : "");
      fs.renameSync(tmp, p);
    }
    let seq = 0;
    let prevHash = "genesis";
    if (lines.length) {
      const tail = JSON.parse(lines[lines.length - 1]);
      seq = tail.seq + 1;
      prevHash = tail.hash;
    }
    const fields = {
      seq,
      ts: Date.now(),
      caseId: spec.caseId,
      ...(spec.turnId ? { turnId: spec.turnId } : {}),
      kind: spec.kind,
      ...(spec.termId ? { termId: spec.termId } : {}),
      ...(spec.sessionId ? { sessionId: spec.sessionId } : {}),
      actor: spec.actor,
      payload: spec.payload,
      prevHash,
    };
    const line = sealEvent(fields);
    const fd = fs.openSync(p, "a");
    try {
      fs.writeSync(fd, line + "\n");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return JSON.parse(line);
  });
}

/// Walk the chain (§1.5): seq strictly increments, prevHash links, every
/// content hash recomputes from the raw bytes.
export function verifyChain(root) {
  const { lines, tornTail } = readLedger(root);
  let prev = "genesis";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let v;
    try {
      v = JSON.parse(line);
    } catch {
      return { ok: false, total: lines.length, brokenAtSeq: i, tornTail };
    }
    const idx = line.lastIndexOf('"hash":"');
    const recomputed = sha256hex(Buffer.from(line.slice(0, idx) + '"hash":""}', "utf8"));
    if (v.seq !== i || v.prevHash !== prev || recomputed !== v.hash) {
      return { ok: false, total: lines.length, brokenAtSeq: v.seq ?? i, tornTail };
    }
    prev = v.hash;
  }
  return { ok: true, total: lines.length, tornTail };
}

// ---- session/turn state (cache; the ledger is the source of truth) ---------

export function readState(root) {
  try {
    return JSON.parse(fs.readFileSync(statePath(root), "utf8"));
  } catch {
    return { sessions: {}, cases: {} };
  }
}

export function writeState(root, state) {
  const p = statePath(root);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, p);
}

/// Case binding for a terminal (§1.4): the state file is a cache; when cold,
/// replay the ledger for the last case_link on this termId — the binding
/// MUST be recoverable from the ledger alone.
export function caseFor(root, termId) {
  const cached = readState(root).cases?.[termId];
  if (cached) return cached;
  const { parsed } = readLedger(root);
  for (let i = parsed.length - 1; i >= 0; i--) {
    if (parsed[i].kind === "case_link" && parsed[i].termId === termId) return parsed[i].caseId;
  }
  return `term:${termId}`;
}
