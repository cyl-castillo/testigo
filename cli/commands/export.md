---
name: export
description: Review and export a signed proof packet (pre-sign review first — nothing leaves unreviewed)
---

Export a signed Testigo proof packet for this project, honoring the
protocol's pre-sign review: the human sees everything a packet would
contain BEFORE anything is signed.

1. If the user named a case, scope with `--case <caseId>`; otherwise export
   the full ledger. First run the review (signs nothing):

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" export --root "${CLAUDE_PROJECT_DIR}" [--case <caseId>]
```

2. Show the user the review table and ask whether any events should be
   manually redacted (secrets, internal paths — things pattern redaction
   can't judge). Do not decide for them.

3. Only after their explicit confirmation, sign and write:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" export --root "${CLAUDE_PROJECT_DIR}" [--case <caseId>] [--redact seq,seq] --yes
```

   Add `--tsa https://freetsa.org/tsr` only if the user wants an RFC 3161
   trusted timestamp (tell them it sends a signature hash — never content —
   to the TSA).

4. Report the packet path, the verifier written alongside it, and the key
   id — remind them the key id is what receivers must compare out-of-band.
