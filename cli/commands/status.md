---
name: status
description: Show this project's Testigo evidence ledger — chain health and recent events
---

Show the user the state of this project's Testigo evidence ledger. Run:

```
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" verify --root "${CLAUDE_PROJECT_DIR}"
node "${CLAUDE_PLUGIN_ROOT}/bin/testigo.mjs" log --root "${CLAUDE_PROJECT_DIR}" -n 15
```

Then summarize plainly: whether the hash chain verifies, how many events are
recorded, which cases exist, and what the most recent activity was. If the
ledger is empty, explain that the plugin's hooks record ambiently from now on
— every prompt, tool call, result and turn end — and that nothing ever leaves
the machine unless the user exports a packet.
