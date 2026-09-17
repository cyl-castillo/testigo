// Start the real CLI together across processes; widen the old shared-temp race.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pause = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const rename = fs.renameSync;
fs.renameSync = function (from, ...args) {
  if (String(from).includes(`${process.env.XDG_DATA_HOME}`) && String(from).endsWith(".json.tmp")) pause(50);
  return rename.call(this, from, ...args);
};

if (process.env.TESTIGO_TEST_BEFORE_LOCK) {
  const mkdir = fs.mkdirSync;
  let paused = false;
  fs.mkdirSync = function (target, ...args) {
    if (!paused && String(target).endsWith(".jsonl.lock")) {
      paused = true;
      fs.writeFileSync(`${process.env.TESTIGO_TEST_BEFORE_LOCK}.ready`, "");
      const deadline = Date.now() + 10_000;
      while (!fs.existsSync(process.env.TESTIGO_TEST_BEFORE_LOCK)) {
        if (Date.now() >= deadline) throw new Error("test barrier timed out");
        pause(10);
      }
    }
    return mkdir.call(this, target, ...args);
  };
}

if (process.env.TESTIGO_TEST_LOCK_EPERM) {
  const mkdir = fs.mkdirSync;
  let remaining = 2;
  fs.mkdirSync = function (target, ...args) {
    if (String(target).endsWith(".jsonl.lock") && remaining-- > 0) {
      throw Object.assign(new Error("injected Windows pending deletion"), { code: "EPERM" });
    }
    return mkdir.call(this, target, ...args);
  };
}

if (process.env.TESTIGO_TEST_FAIL_APPEND) {
  const open = fs.openSync;
  fs.openSync = function (target, flags, ...args) {
    if (String(target).endsWith(".jsonl") && flags === "a") {
      throw Object.assign(new Error("injected append failure"), { code: "EIO" });
    }
    return open.call(this, target, flags, ...args);
  };
}

const start = new Promise((resolve) => process.once("message", resolve));
process.send("ready");
await start;
process.disconnect();
process.argv = [process.execPath, fileURLToPath(new URL("./bin/testigo.mjs", import.meta.url)), ...process.argv.slice(2)];
if (process.argv[2] === "hold-lock") {
  const { withLock } = await import("./lib/ledger.mjs");
  withLock(process.argv[3], () => {
    fs.writeFileSync(path.join(process.env.XDG_DATA_HOME, "holder-ready"), "");
    pause(30_000);
  });
  process.exit(0);
}
await import("./bin/testigo.mjs");
