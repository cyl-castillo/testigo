import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { verifyPacket } from "../conformance/verify.mjs";

const { chromium } = createRequire(import.meta.url)("playwright");
const readJSON = (url) => JSON.parse(fs.readFileSync(url, "utf8"));
const vector = (name) => readJSON(new URL(`../conformance/vectors/${name}.proofpack.json`, import.meta.url));
const statement = (packet) => JSON.parse(Buffer.from(packet.envelope.payload, "base64"));
// Harmless execution marker; data: avoids making any network request.
const attack = '<img src="data:," onerror="window.__xss=1"> &amp; <b>literal</b>';
// Published, disposable conformance key (see conformance/README.md).
const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x42)]),
  format: "der", type: "pkcs8",
});

function mutate(edit, validSignature = false, name = "valid-redacted-stub") {
  const packet = vector(name);
  const st = statement(packet);
  edit(st.predicate, packet);
  const payload = Buffer.from(JSON.stringify(st));
  packet.envelope.payload = payload.toString("base64");
  if (validSignature) {
    const type = packet.envelope.payloadType;
    const pae = Buffer.concat([Buffer.from(`DSSEv1 ${type.length} ${type} ${payload.length} `), payload]);
    packet.envelope.signatures[0].sig = crypto.sign(null, pae, privateKey).toString("base64");
  }
  return packet;
}

const corpora = ["conformance", "predicate"].map((name) => {
  const dir = new URL(`../${name}/vectors/`, import.meta.url);
  return { name, dir, manifest: readJSON(new URL("manifest.json", dir)) };
});

test("reference conformance and session-chain manifests", () => {
  for (const { dir, manifest } of corpora) for (const v of manifest.vectors) {
    const got = verifyPacket(readJSON(new URL(v.file, dir)), manifest.enforce ?? {});
    for (const [key, expected] of Object.entries(v.expect)) {
      if (key === "counts") {
        for (const [count, value] of Object.entries(expected)) assert.equal(got.counts[count], value, `${v.file}: ${count}`);
      } else assert.equal(got[key], expected, `${v.file}: ${key}`);
    }
  }
});

test("browser rendering treats packet values as text", async (t) => {
  const browser = await chromium.launch({ headless: true, ...(process.env.BROWSER_CHANNEL ? { channel: process.env.BROWSER_CHANNEL } : {}) });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const target = process.env.VERIFIER_HTML ? pathToFileURL(process.env.VERIFIER_HTML) : new URL("testigo-verifier.html", import.meta.url);
    await page.goto(target.href);

    async function render(packet) {
      await page.evaluate(async (packet) => {
        window.__xss = 0;
        await load(new File([JSON.stringify(packet)], "test.proofpack.json", { type: "application/json" }));
        // Let queued image error / SVG load handlers fire before inspecting.
        await new Promise((resolve) => setTimeout(resolve, 50));
      }, packet);
      const state = await page.evaluate(() => ({
        executed: window.__xss,
        checks: document.querySelector("#checks").textContent,
        meta: document.querySelector("#meta").textContent,
        tsp: document.querySelector("#tsp").textContent,
        rows: [...document.querySelectorAll("#events tr")].slice(1).map((tr) => [...tr.cells].map((td) => td.textContent)),
        // None of the packet display paths should create active markup.
        injected: document.querySelectorAll("#result img, #result svg, #result script, #result iframe, #result b, #result [onerror], #result [onload]").length,
        nestedCells: document.querySelectorAll("#events td *").length,
      }));
      assert.deepEqual(errors, [], "no browser exceptions");
      assert.equal(state.executed, 0, "packet event handler must not execute");
      assert.equal(state.injected, 0, "packet markup must not create elements");
      assert.equal(state.nestedCells, 0, "event cells contain only text");
      return state;
    }

    for (const field of ["stub.seq", "stub.kind", "event.seq"]) for (const signed of [false, true]) {
      await t.test(`${field}, ${signed ? "valid" : "invalid"} signature`, async () => {
        let index;
        const packet = mutate((pred) => {
          index = pred.events.findIndex((e) => field.startsWith("stub.") ? e.stub : e.line);
          const e = pred.events[index];
          if (e.stub) e.stub[field.split(".")[1]] = attack;
          else { const v = JSON.parse(e.line); v.seq = attack; e.line = JSON.stringify(v); }
        }, signed);
        const state = await render(packet);
        assert.ok(state.checks.includes(signed ? "Signature valid" : "Signature INVALID"));
        assert.equal(state.rows[index][field === "stub.kind" ? 3 : 0], field === "stub.kind" ? `${attack} (other case, linkage only)` : attack);
        assert.ok(state.rows.every((row) => row.length === 4));
      });
    }

    await t.test("all event detail branches, actor, unknown kind and redaction markers", async () => {
      const cases = [
        ["prompt", { prompt: attack }, attack],
        ["approval_request", { tool: attack }, `tool=${attack}`],
        ["approval_decision", { decision: attack, reason: attack, tool: attack }, `${attack} — ${attack} (tool=${attack})`],
        ["tool_result", { tool: attack }, `tool=${attack}`],
        ["snapshot", { commitSha: attack }, `sha=${attack.slice(0, 10)}`],
        ["turn_end", { filesChanged: [{ status: attack, path: attack }] }, `${attack} ${attack}`.slice(0, 200)],
        ["case_link", {}, attack],
        ["job_run", { jobName: attack, status: attack }, `${attack}: ${attack}`],
        ["session_start", { engine: attack, model: attack }, `${attack} model=${attack}`],
        ["model_switch", { from: attack, to: attack }, `${attack} → ${attack}`],
        ["tool_call", { tool: attack }, `tool=${attack}`],
        [attack, {}, ""],
      ];
      const packet = mutate((pred) => {
        pred.events = cases.map(([kind, payload], seq) => ({
          line: JSON.stringify({ seq, kind, actor: attack, caseId: attack, payload }), redacted: seq % 2 === 1,
        }));
      });
      const state = await render(packet);
      assert.deepEqual(state.rows, cases.map(([kind, , detail], seq) => [String(seq), kind + (seq % 2 ? " ⚠" : ""), attack, detail]));
      assert.equal(await page.locator("#events td.kind").count(), cases.length);
    });

    await t.test("metadata, process context and timestamp display paths", async () => {
      const packet = mutate((pred, packet) => {
        delete pred.exportedAtMs;
        Object.assign(pred, {
          caseId: attack, project: attack, exportedAt: attack, generator: attack, owner: attack,
          range: { ...pred.range, fromSeq: attack, toSeq: attack },
          provider: { harness: { name: attack, version: attack }, agent: { name: attack }, languageModels: [{ resolved: attack }] },
          contextArtifacts: [{ tags: [attack], uri: attack }],
        });
        packet.timestamp.tsaUrl = attack;
      }, false, "valid-timestamped");
      const state = await render(packet);
      assert.equal(state.meta.split(attack).length - 1, 13, "all declared metadata values remain literal");
      assert.ok(state.checks.includes(attack), "TSA warning remains literal");
      assert.ok(state.tsp.includes(attack), "TSA metadata remains literal");
      const link = page.locator("#tsp a");
      assert.match(await link.getAttribute("href"), /^blob:/);
      assert.equal(await link.getAttribute("download"), "packet.tsr");
      packet.timestamp.type = attack;
      const unknownTimestamp = await render(packet);
      assert.ok(unknownTimestamp.checks.includes(`Timestamp of unknown type "${attack}"`));
      assert.equal(unknownTimestamp.tsp, "", "previous timestamp is cleared");
      packet.format = attack;
      const unknownFormat = await render(packet);
      assert.ok(unknownFormat.checks.includes(`Unknown format: ${attack}`));
      assert.deepEqual(unknownFormat.rows, [], "previous event rows are cleared");
      assert.equal(unknownFormat.meta, "");
    });

    await t.test("external evidence preserves formatting and renders every field as text", async () => {
      const ordinary = await render(vector("valid-external-evidence"));
      assert.equal(ordinary.rows[2][3], "claude-code-transcript · sha256 b8e121f9e847… · [REDACTED:home]/.claude/projects/proj/s-1.jsonl");
      assert.equal(ordinary.rows[4][3], "anthropic-compliance-api · sha256 1a0ff373fab7… · compliance-export-s-1.json · org export of session s-1");
      for (const field of ["source", "sha256", "uri", "note"]) for (const signed of [false, true]) {
        // A complete HTML tag within the hash's 12-character display limit.
        const value = field === "sha256" ? "<b>hash</b>" : attack;
        const payload = { source: "transcript", sha256: "a".repeat(64), uri: "record.json", note: "captured", [field]: value };
        const packet = mutate((pred) => {
          const e = pred.events[2];
          e.line = JSON.stringify({ ...JSON.parse(e.line), payload });
        }, signed, "valid-external-evidence");
        const state = await render(packet);
        assert.ok(state.checks.includes(signed ? "Signature valid" : "Signature INVALID"), `${field}: signature`);
        assert.equal(state.rows[2][3], `${payload.source} · sha256 ${payload.sha256.slice(0, 12)}… · ${payload.uri} · ${payload.note}`, `${field}: literal detail`);
      }
    });

    await t.test("all golden vectors render with existing verification messages", async () => {
      const failures = {
        format: "Unknown format:", keyid: "Embedded key id does not match", signature: "Signature INVALID",
        digest: "Subject digest does NOT match", linkage: "Hash chain linkage BROKEN", contentHash: "failed content hash recomputation",
        redactionCount: "Declared redactionCount", timestamps: "Declared session window does NOT match", processContext: "Process context malformed",
      };
      for (const { dir, manifest } of corpora) for (const v of manifest.vectors) {
        const packet = readJSON(new URL(v.file, dir));
        const state = await render(packet);
        if (v.expect.firstFailure in failures) assert.ok(state.checks.includes(failures[v.expect.firstFailure]), v.file);
        // The HTML verifier does not enforce the draft's migration guards.
        if (v.expect.valid) assert.ok(state.checks.includes("Signature valid"), v.file);
        if (v.expect.timestamp === "mismatch") assert.ok(state.checks.includes("imprint does not match"), v.file);
        if (v.expect.timestamp === "declared") assert.ok(state.checks.includes("NOT cryptographically verified"), v.file);
        if (v.expect.firstFailure !== "format") {
          const events = statement(packet).predicate.events;
          assert.equal(state.rows.length, events.length, v.file);
          assert.ok(state.rows.every((row) => row.length === 4), v.file);
          for (const [i, e] of events.entries()) if (e.stub) {
            assert.deepEqual(state.rows[i], [String(e.stub.seq), "stub", "—", `${e.stub.kind ?? ""} (other case, linkage only)`], v.file);
          }
        }
      }
    });

    await t.test("byte-exact content hashes: one failed event, nothing else", async () => {
      // Formerly a vm-simulated DOM check in conformance/hash.test.mjs; the
      // row rendering is DOM-built now, so it runs where the page really runs.
      const files = [
        "valid-minimal", "valid-redacted-stub", "valid-hash-whitespace", "valid-payload-hash",
        "invalid-member-after-hash", "invalid-payload-after-hash", "invalid-escaped-payload-after-hash", "invalid-hash-trailing-whitespace",
      ];
      for (const name of files) {
        const state = await render(vector(name));
        for (const text of ["Signature valid", "Subject digest matches", "Hash chain linkage intact"]) assert.ok(state.checks.includes(text), `${name}: ${text}`);
        // The one-line summary also carries .fail; count the individual checks only.
        const failures = await page.locator("#checks .fail:not(#summary)").allTextContents();
        if (name.startsWith("invalid-")) {
          assert.equal(failures.length, 1, name);
          assert.match(failures[0], /1 event\(s\) failed content hash recomputation/, name);
        } else {
          assert.deepEqual(failures, [], name);
        }
      }
    });

    await t.test("file picker still loads an ordinary packet", async () => {
      await page.reload();
      const packet = vector("valid-minimal");
      await page.locator("#file").setInputFiles({ name: "sample.proofpack.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(packet)) });
      await page.waitForSelector("#events table");
      assert.equal(await page.locator("#events td").count(), 20);
      assert.equal(await page.locator("#checks .fail").count(), 0);
      assert.deepEqual(errors, []);
    });
  } finally {
    await browser.close();
  }
});
