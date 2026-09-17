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

/// mkdir is atomic. Record a unique owner inside the directory so a slow
/// live writer cannot lose its lock just because it is over 10s old.
/// Only a confirmed dead owner may be reclaimed; unknown ownership times
/// out safely. All participants must run on the same host (PID namespace).
export function withLock(target, fn) {
  const lock = `${target}.lock`;
  const owner = `${process.pid}-${crypto.randomUUID()}`;
  const ownerPath = path.join(lock, owner);
  fs.mkdirSync(path.dirname(lock), { recursive: true });
  const deadline = performance.now() + 5000;
  const sleeper = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    try {
      fs.mkdirSync(lock);
      break;
    } catch (e) {
      // Windows can report a directory pending deletion as EPERM/EACCES
      // while the previous owner releases it. Retry within the same bound.
      const pendingDelete = process.platform === "win32" && ["EPERM", "EACCES"].includes(e.code);
      if (e.code !== "EEXIST" && !pendingDelete) throw e;
      try {
        const entries = fs.readdirSync(lock);
        const match = entries.length === 1 && /^(\d+)-[0-9a-f-]{36}$/.exec(entries[0]);
        if (match && Number(match[1]) > 0) {
          let dead = false;
          try { process.kill(Number(match[1]), 0); }
          catch (error) { dead = error.code === "ESRCH"; }
          if (dead) {
            // The unique filename elects one reclaimer. Other contenders
            // must not remove the directory if this unlink fails: it may
            // already belong to a new writer.
            fs.unlinkSync(path.join(lock, entries[0]));
            fs.rmdirSync(lock);
          }
        }
      } catch {} // another contender may have reclaimed it; retry within the deadline
      if (performance.now() >= deadline) throw new Error(`ledger lock stuck: ${lock}`);
      Atomics.wait(sleeper, 0, 0, 10);
    }
  }
  try {
    fs.writeFileSync(ownerPath, "", { flag: "wx" });
    return fn();
  } finally {
    try { fs.unlinkSync(ownerPath); } catch {}
    try { fs.rmdirSync(lock); } catch {}
  }
}

/// Raw lines, byte-exact (hashes were computed over these bytes). Only an
/// unparseable, unterminated final line is a torn tail. A complete final
/// record without a newline is retained and needs only its separator.
export function readLedger(root) {
  const p = ledgerPath(root);
  if (!fs.existsSync(p)) return { lines: [], parsed: [], tornTail: false, missingNewline: false, tailOffset: 0 };
  const raw = fs.readFileSync(p);
  const tailOffset = raw.lastIndexOf(0x0a) + 1;
  const unterminated = raw.length > tailOffset;
  const physicalLines = raw.toString("utf8").split("\n");
  const lines = [];
  const parsed = [];
  let tornTail = false;
  for (let i = 0; i < physicalLines.length; i++) {
    const line = physicalLines[i];
    if (line.trim() === "") continue;
    try {
      parsed.push(JSON.parse(line));
      lines.push(line);
    } catch {
      if (unterminated && i === physicalLines.length - 1) {
        tornTail = true;
      } else {
        throw new Error(`unparseable ledger line at index ${i} — tampering or corruption`);
      }
    }
  }
  return { lines, parsed, tornTail, missingNewline: unterminated && !tornTail, tailOffset };
}

// writeSync may consume fewer bytes than requested. Use byte offsets (not
// string slices) so a short write inside a UTF-8 character is resumed exactly.
function writeAll(fd, bytes) {
  for (let offset = 0; offset < bytes.length;) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (written === 0) throw new Error("ledger write made no progress");
    offset += written;
  }
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

/// Append an event (or an ordered batch): lock → chain → repair a torn tail /
/// missing separator → write → fsync. `spec` = {caseId, turnId?, kind, termId?, sessionId?, actor, payload},
/// or a synchronous factory receiving state derived from this locked tail.
/// Binding selection and the append therefore share one consistency boundary.
export function append(root, spec) {
  const p = ledgerPath(root);
  return withLock(p, () => {
    const { lines, parsed, tornTail, missingNewline, tailOffset } = readLedger(root);
    if (typeof spec === "function") spec = spec(stateFromEvents(parsed));
    if (!spec) return;
    const specs = Array.isArray(spec) ? spec : [spec];
    if (!specs.length) return;
    let seq = 0;
    let prevHash = "genesis";
    if (lines.length) {
      const tail = JSON.parse(lines[lines.length - 1]);
      seq = tail.seq + 1;
      prevHash = tail.hash;
    }
    const batch = specs.map((entry) => {
      const fields = {
        seq,
        ts: Date.now(),
        caseId: entry.caseId,
        ...(entry.turnId ? { turnId: entry.turnId } : {}),
        kind: entry.kind,
        ...(entry.termId ? { termId: entry.termId } : {}),
        ...(entry.sessionId ? { sessionId: entry.sessionId } : {}),
        actor: entry.actor,
        payload: entry.payload,
        prevHash,
      };
      const line = sealEvent(fields);
      seq++;
      prevHash = JSON.parse(line).hash;
      return line;
    });
    if (tornTail) {
      // Shorten to the last separator, preserving every prefix byte.
      // Windows requires a writable (not append-only) handle to truncate.
      const repairFd = fs.openSync(p, "r+");
      try {
        fs.ftruncateSync(repairFd, tailOffset);
        fs.fsyncSync(repairFd);
      } finally {
        fs.closeSync(repairFd);
      }
    }
    const fd = fs.openSync(p, "a");
    try {
      if (missingNewline) {
        writeAll(fd, Buffer.from("\n"));
        // Commit the separator before any next-event bytes can reach disk.
        fs.fsyncSync(fd);
      }
      writeAll(fd, Buffer.from(batch.join("\n") + "\n", "utf8"));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return Array.isArray(spec) ? batch.map((line) => JSON.parse(line)) : JSON.parse(batch[0]);
  });
}

/// Walk the chain (§1.5): seq strictly increments, prevHash links, every
/// content hash recomputes from the raw bytes.
export function verifyChain(root, snapshot = readLedger(root)) {
  const { lines, tornTail } = snapshot;
  let prev = "genesis";
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let v;
    try {
      v = JSON.parse(line);
    } catch {
      return { ok: false, total: lines.length, brokenAtSeq: i, tornTail };
    }
    // Require the final member and empty only its value. Rebuilding the
    // suffix would silently drop added members (including a second payload).
    const field = /("hash"\s*:\s*")([0-9a-f]{64})("\s*}\s*)$/.exec(line);
    const unhashed = field && field[2] === v.hash
      ? line.slice(0, field.index) + field[1] + field[3]
      : null;
    const recomputed = unhashed === null ? null : sha256hex(Buffer.from(unhashed, "utf8"));
    if (unhashed === null || v.seq !== i || v.prevHash !== prev || recomputed !== v.hash) {
      return { ok: false, total: lines.length, brokenAtSeq: v.seq ?? i, tornTail };
    }
    prev = v.hash;
  }
  return { ok: true, total: lines.length, tornTail };
}

// ---- session/turn state (derived from the ledger, never separately written) ----

function stateFromEvents(events) {
  const state = { sessions: Object.create(null), cases: Object.create(null) };
  for (const event of events) {
    if (event.kind === "case_link" && event.termId) state.cases[event.termId] = event.caseId;
    if (!event.sessionId) continue;
    if (event.kind === "prompt" && event.turnId) {
      state.sessions[event.sessionId] = { turnId: event.turnId, lastTs: event.ts };
    } else if (event.kind === "turn_end" && state.sessions[event.sessionId]?.turnId === event.turnId) {
      delete state.sessions[event.sessionId];
    }
  }
  return state;
}

/// A snapshot for readers. Writers must use append's factory so the snapshot
/// and resulting event cannot be interleaved with another writer.
export function readState(root) {
  return stateFromEvents(readLedger(root).parsed);
}

/// Case bindings (§1.4) come from case_link events, including when an old
/// state JSON remains on disk from an earlier version. That cache is ignored.
export function caseFor(root, termId, state = readState(root)) {
  return state.cases[termId] ?? `term:${termId}`;
}
