---
name: verify-gates
description: Run ntod-scan's real verification gates before reporting any change done — cargo fmt, clippy -D warnings, workspace tests. Use when finishing a code change in this repo, before claiming work is done, or when asked how to verify ntod-scan.
triggers:
  - model
---

# verify-gates

Run all three from the workspace root before reporting done:

```sh
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

- `apps/web` has no build step — there is no npm/vite check to run.
- `ntod-analysis` has criterion benches; `cargo test` compiles them too.
