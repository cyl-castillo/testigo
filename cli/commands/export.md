---
name: export
description: Inspect the complete unsigned statement, then sign that reviewed snapshot
---

Export a signed Testigo proof packet for this project, honoring the
protocol's pre-sign review: give the human access to the complete final
statement BEFORE anything is signed, then sign that exact saved snapshot.

1. If the user named a case, scope with `--case <caseId>`; otherwise export
   the full ledger. Include any requested `--owner`, `--model`, and
   `--redact` options when generating the review (signs nothing):

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" export --root "${CLAUDE_PROJECT_DIR}" [--case <caseId>] [--owner <owner>] [--model <model>] [--redact seq,seq]
```

   If the user only wants to inspect content without saving a review, add
   `--review -` to print the complete post-redaction statement. This creates
   no review file and cannot be combined with `--yes`. To sign later,
   generate and inspect a saved review as described below.

2. The command reports the path to a complete unsigned JSON statement.
   Open/read that file and give the user its path so they can inspect it in
   an editor. It contains every final event line and stub, after automatic
   and requested redactions, plus all signed metadata: owner, models,
   instruction-file paths/digests, project, timestamps, hashes and range.
   To print the full file, use:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" export --review "<review-file>"
```

   A summary, excerpt, or tool output that has been truncated is NOT the
   complete review. If output is clipped, read the file in sections and
   keep the full file accessible to the user. Do not claim they have seen
   all content from a summary alone. Ask whether any payloads should be
   manually redacted; do not decide for them. Explain that `--redact`
   replaces only the payload: event metadata remains. If sensitive
   metadata remains unacceptable, do not sign the packet.

   If they request redactions or changes to declarations, repeat step 1
   with all intended options, inspect the NEW file, and ask for confirmation
   of that version. Do not edit the saved statement directly. Earlier
   review files remain local and may contain content removed in later ones.
   They contain post-redaction content, but retained text and metadata may
   still be sensitive; they are not automatically safe to retain or share.

3. Only after their explicit confirmation of the final file, sign and write
   that file. Use the exact returned review path; do not rerun a live-ledger
   export with `--yes` alone, which skips review and can include new events:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" export --root "${CLAUDE_PROJECT_DIR}" --review "<review-file>" --yes
```

   Keep the same project root: signing re-verifies its ledger and checks
   every reviewed event/stub against the original sequence and linkage,
   with byte-exact matching for unredacted lines. Later valid appends are
   allowed. A missing, corrupt, or replaced source ledger prevents signing;
   report that error instead of bypassing it with a live-ledger `--yes` export.

   Add `--tsa https://freetsa.org/tsr` only if the user wants an RFC 3161
   trusted timestamp (tell them it sends a signature hash — never content —
   to the TSA). Preserve any requested `--out` directory. Signing adds the
   public key/signature and optional TSA response outside the reviewed
   statement; the statement bytes, including export time, stay unchanged.

4. Report the packet path, the verifier written alongside it, and the key
   id — remind them the key id is what receivers must compare out-of-band.
