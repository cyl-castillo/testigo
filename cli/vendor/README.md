# vendor/ — generated, do not edit

`core/` is a byte-identical copy of [`packages/core`](../../packages/core),
regenerated with `node scripts/vendor.mjs sync` and checked in CI
(`node scripts/vendor.mjs check`). It exists because Claude Code installs
only this plugin directory, so the engine-neutral core has to travel inside
it. Fix things in `packages/core`, then sync.
