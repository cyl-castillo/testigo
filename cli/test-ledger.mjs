import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { append, ledgerPath, readLedger, verifyChain } from "./lib/ledger.mjs";

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "testigo-ledger-test-"));
const oldDataHome = process.env.XDG_DATA_HOME;
process.env.XDG_DATA_HOME = sandbox;
after(() => {
  if (oldDataHome === undefined) delete process.env.XDG_DATA_HOME;
  else process.env.XDG_DATA_HOME = oldDataHome;
  fs.rmSync(sandbox, { recursive: true, force: true });
});

const add = (root, text) => append(root, {
  caseId: "tail-test", kind: "prompt", actor: "human", payload: { text },
});
const bytes = root => fs.readFileSync(ledgerPath(root));
function check(root, events) {
  assert.deepEqual(readLedger(root).parsed, events);
  assert.deepEqual(verifyChain(root), { ok: true, total: events.length, tornTail: false });
  assert.equal(readLedger(root).missingNewline, false);
}
function patchFs(overrides, run) {
  const originals = Object.fromEntries(Object.keys(overrides).map(key => [key, fs[key]]));
  Object.assign(fs, overrides);
  try { return run(); } finally { Object.assign(fs, originals); }
}

test("complete final JSON without LF survives two subsequent appends", () => {
  for (const count of [1, 2]) {
    const root = path.join(sandbox, `missing-newline-${count}`);
    const events = Array.from({ length: count }, (_, i) => add(root, `evidence ${i}: ñ 🔒`));
    fs.truncateSync(ledgerPath(root), bytes(root).length - 1);
    const before = bytes(root);
    const read = readLedger(root);
    assert.deepEqual(read.parsed, events);
    assert.equal(read.tornTail, false);
    assert.equal(read.missingNewline, true);
    assert.equal(verifyChain(root).total, count);
    assert.deepEqual(bytes(root), before, "reading never repairs the ledger");
    events.push(add(root, "next"));
    check(root, events);
    events.push(add(root, "next again"));
    check(root, events);
    assert.deepEqual(bytes(root).subarray(0, before.length + 1), Buffer.concat([before, Buffer.from("\n")]));
  }
});

test("only an unterminated partial record is removed, preserving every prefix byte", () => {
  for (const count of [0, 2]) {
    const root = path.join(sandbox, `torn-${count}`);
    const events = Array.from({ length: count }, (_, i) => add(root, `preserved ${i}: ñ 🔒`));
    fs.mkdirSync(path.dirname(ledgerPath(root)), { recursive: true });
    if (!count) fs.writeFileSync(ledgerPath(root), "");
    fs.appendFileSync(ledgerPath(root), "\n \t\n");
    const prefix = bytes(root);
    // Include a torn UTF-8 code point: repair must use a byte offset.
    fs.appendFileSync(ledgerPath(root), Buffer.concat([Buffer.from('{"seq":2,"payload":"'), Buffer.from("🔒").subarray(0, 2)]));
    const before = bytes(root);
    const read = readLedger(root);
    assert.equal(read.tornTail, true);
    assert.equal(read.missingNewline, false);
    assert.equal(read.tailOffset, prefix.length);
    assert.deepEqual(read.parsed, events);
    assert.deepEqual(bytes(root), before);
    events.push(add(root, "after crash"));
    check(root, events);
    assert.deepEqual(bytes(root).subarray(0, prefix.length), prefix);
  }
});

test("terminated corrupt records (including the old concatenation) fail without mutation", () => {
  for (const suffix of ["\n", "\n\n \t", '\n{"seq":1}\n']) {
    const root = path.join(sandbox, `corrupt-${Buffer.from(suffix).toString("hex")}`);
    add(root, "preserved");
    fs.appendFileSync(ledgerPath(root), '{"seq":1' + suffix);
    const before = bytes(root);
    assert.throws(() => readLedger(root), /tampering or corruption/);
    assert.throws(() => verifyChain(root), /tampering or corruption/);
    assert.throws(() => add(root, "must fail"), /tampering or corruption/);
    assert.deepEqual(bytes(root), before);
  }
  const root = path.join(sandbox, "old-concatenation");
  add(root, "prefix"); add(root, "first"); add(root, "second");
  const lines = bytes(root).toString("utf8").trimEnd().split("\n");
  fs.writeFileSync(ledgerPath(root), lines[0] + "\n" + lines[1] + lines[2] + "\n");
  const before = bytes(root);
  assert.throws(() => add(root, "must not discard evidence"), /tampering or corruption/);
  assert.deepEqual(bytes(root), before);
});

test("CLI verify reports the physical line index and validates a manual separator repair", () => {
  const root = path.join(sandbox, "verify-old-concatenation");
  const events = [add(root, "prefix"), add(root, "literal }{ in a payload"), add(root, "last")];
  const lines = readLedger(root).lines;
  // A blank line makes the physical index differ from the event sequence.
  const prefix = lines[0] + "\n\n";
  fs.writeFileSync(ledgerPath(root), prefix + lines[1] + lines[2] + "\n");
  const before = bytes(root);
  const verify = () => spawnSync(process.execPath, [
    fileURLToPath(new URL("./bin/testigo.mjs", import.meta.url)), "verify", "--root", root,
  ], { encoding: "utf8", timeout: 10_000 });

  const corrupt = verify();
  assert.ifError(corrupt.error);
  assert.equal(corrupt.status, 1);
  assert.match(corrupt.stderr, /unparseable ledger line at index 2 — tampering or corruption/);
  assert.doesNotMatch(corrupt.stdout, /chain ok/);
  assert.deepEqual(bytes(root), before, "verification leaves the evidence intact");

  // Insert only the missing separator, leaving the payload's }{ untouched.
  const boundary = Buffer.byteLength(prefix + lines[1], "utf8");
  const repaired = Buffer.concat([before.subarray(0, boundary), Buffer.from("\n"), before.subarray(boundary)]);
  fs.writeFileSync(ledgerPath(root), repaired);
  const restored = verify();
  assert.ifError(restored.error);
  assert.equal(restored.status, 0, restored.stderr);
  assert.match(restored.stdout, /chain ok: 3 events/);
  assert.deepEqual(bytes(root), repaired);
  check(root, events);
});

test("whitespace-only unterminated tails are separated without changing prior bytes", () => {
  const root = path.join(sandbox, "whitespace");
  const first = add(root, "first");
  fs.appendFileSync(ledgerPath(root), " \t");
  const before = bytes(root);
  const second = add(root, "second");
  check(root, [first, second]);
  assert.deepEqual(bytes(root).subarray(0, before.length + 1), Buffer.concat([before, Buffer.from("\n")]));
});

test("short writes resume by bytes, including inside UTF-8, before fsync", () => {
  const root = path.join(sandbox, "short-writes");
  const originalWrite = fs.writeSync;
  const originalSync = fs.fsyncSync;
  let writes = 0;
  let syncs = 0;
  const event = patchFs({
    writeSync(fd, buffer, offset, length) {
      writes++;
      return originalWrite(fd, buffer, offset, Math.min(1, length));
    },
    fsyncSync(fd) {
      syncs++;
      assert.ok(bytes(root).toString("utf8").endsWith("\n"));
      originalSync(fd);
    },
  }, () => add(root, "ñ 🔒"));
  assert.equal(writes, bytes(root).length);
  assert.equal(syncs, 1);
  check(root, [event]);
});

test("zero-byte writes throw and release the lock", () => {
  const root = path.join(sandbox, "zero-write");
  let calls = 0;
  patchFs({ writeSync() { calls++; return 0; } }, () => {
    assert.throws(() => add(root, "unwritten"), /no progress/);
  });
  assert.equal(calls, 1);
  assert.equal(bytes(root).length, 0);
  const event = add(root, "retry");
  check(root, [event]);
});

test("failed writes retain complete JSON and recover partial JSON on the next append", () => {
  for (const cut of ["partial", "utf8", "before-newline"]) {
    const root = path.join(sandbox, `failed-write-${cut}`);
    const first = add(root, "first");
    const prefix = bytes(root);
    const originalWrite = fs.writeSync;
    let calls = 0;
    let attempted;
    patchFs({
      writeSync(fd, buffer, offset, length) {
        if (calls++) throw new Error("injected write failure");
        attempted = JSON.parse(buffer.toString("utf8"));
        const limit = cut === "partial" ? 10 : cut === "utf8" ? buffer.indexOf(Buffer.from("🔒")) + 2 : length - 1;
        return originalWrite(fd, buffer, offset, limit);
      },
    }, () => assert.throws(() => add(root, "interrupted 🔒"), /injected write failure/));
    const complete = cut === "before-newline";
    assert.equal(readLedger(root).tornTail, !complete);
    assert.equal(readLedger(root).missingNewline, complete);
    const next = add(root, "retry");
    check(root, complete ? [first, attempted, next] : [first, next]);
    assert.deepEqual(bytes(root).subarray(0, prefix.length), prefix);
  }
});

test("repairs are synced before the next event; a failed repair sync stops append", () => {
  for (const tail of ["complete", "partial"]) {
    const root = path.join(sandbox, `repair-sync-${tail}`);
    const first = add(root, "first");
    const prefix = bytes(root);
    if (tail === "complete") fs.truncateSync(ledgerPath(root), prefix.length - 1);
    else fs.appendFileSync(ledgerPath(root), '{"seq":1');
    patchFs({
      fsyncSync() {
        assert.deepEqual(bytes(root), prefix, "only repair bytes precede its sync");
        throw new Error("injected repair sync failure");
      },
    }, () => assert.throws(() => add(root, "must not be written"), /injected repair sync failure/));
    assert.deepEqual(bytes(root), prefix);
    const next = add(root, "retry");
    check(root, [first, next]);
  }
});

test("failed final fsync reports failure but never discards a fully written event", () => {
  const root = path.join(sandbox, "final-sync-failure");
  patchFs({ fsyncSync() { throw new Error("injected final sync failure"); } }, () => {
    assert.throws(() => add(root, "written but unacknowledged"), /injected final sync failure/);
  });
  const [written] = readLedger(root).parsed;
  const next = add(root, "retry");
  check(root, [written, next]);
});
