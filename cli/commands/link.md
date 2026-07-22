---
name: link
description: Bind this session's evidence to a case (e.g. jira:PROJ-42, github:org/repo#5)
---

Bind the current session to the case the user names (argument, e.g.
`jira:PROJ-42` or `github:org/repo#5`). Run:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" link <caseId> --root "${CLAUDE_PROJECT_DIR}"
```

If the user gave no case id, ask for one — suggest the tracker-qualified
form (`jira:KEY`, `github:org/repo#N`). Confirm the link and mention that
subsequent events in this session will carry the case, so a proof packet
for it can be exported later with `/testigo:export`.
