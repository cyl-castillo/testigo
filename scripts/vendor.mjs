#!/usr/bin/env node
// Vendors packages/core into the plugin(s). Claude Code installs only a
// plugin's own subdirectory (copied to ~/.claude/plugins/cache/…), so a plugin
// cannot import ../../packages/core at runtime: it ships a byte-identical
// copy under <plugin>/vendor/core/, and CI fails when the copy drifts.
//
//   node scripts/vendor.mjs sync    # regenerate every vendored copy
//   node scripts/vendor.mjs check   # exit 1 if any copy differs (CI gate)
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SOURCE = path.join(REPO, "packages", "core");
const TARGETS = [path.join(REPO, "cli", "vendor", "core")];
const files = () => fs.readdirSync(SOURCE).filter((f) => f.endsWith(".mjs")).sort();

function sync() {
  for (const target of TARGETS) {
    fs.rmSync(target, { recursive: true, force: true });
    fs.mkdirSync(target, { recursive: true });
    for (const f of files()) fs.copyFileSync(path.join(SOURCE, f), path.join(target, f));
    console.log(`vendored ${files().length} files → ${path.relative(REPO, target)}`);
  }
}

function check() {
  const drift = [];
  for (const target of TARGETS) {
    const have = fs.existsSync(target) ? fs.readdirSync(target).filter((f) => f.endsWith(".mjs")).sort() : [];
    for (const f of new Set([...files(), ...have])) {
      const a = path.join(SOURCE, f), b = path.join(target, f);
      if (!fs.existsSync(a) || !fs.existsSync(b) || !fs.readFileSync(a).equals(fs.readFileSync(b))) drift.push(path.relative(REPO, b));
    }
  }
  if (drift.length) {
    console.error(`vendored core out of date:\n  ${drift.join("\n  ")}\nrun: node scripts/vendor.mjs sync`);
    process.exit(1);
  }
  console.log("vendored core matches packages/core");
}

const cmd = process.argv[2];
if (cmd === "sync") sync();
else if (cmd === "check") check();
else { console.error("usage: node scripts/vendor.mjs sync|check"); process.exit(2); }
