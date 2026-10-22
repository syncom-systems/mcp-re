<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to MCP-RE

Thank you for considering a contribution to MCP-RE.

MCP-RE is an experimental third-party security extension proposal for the Model Context Protocol. Contributions should preserve the project's security boundaries and must avoid implying official MCP status unless the extension is accepted through the official MCP process.

## Licensing of contributions

Unless otherwise stated, all contributions intentionally submitted to this repository are licensed under the Apache License, Version 2.0.

By submitting a contribution, you represent that you have the right to submit it under the Apache License, Version 2.0.

## Contribution expectations

Contributions should:

- preserve the distinction between MCP-RE Core, policy profiles, transport hardening, and deployment-specific integrations;
- include tests for security-relevant behavior;
- fail closed on malformed, unknown, or unsupported security inputs;
- avoid broadening the project's public claims without updating the Security Boundary Document;
- update documentation and conformance manifests when behavior changes.

## Security-sensitive changes

Changes touching any of the following areas require special review:

- signature verification;
- canonicalization;
- nonce/replay handling;
- trust resolution;
- authorization profile evaluation;
- transport binding or mTLS;
- key loading or signing;
- verified-context injection;
- inner-server isolation;
- conformance vectors;
- public security claims.

Security-sensitive changes should include positive tests, negative/fail-closed tests, traceability to requirements, and notes about what is not covered.

## Experimental status

MCP-RE is incubating under a third-party extension identifier. Do not describe it as an official MCP extension unless accepted through the official MCP governance process.

## Developer workflow

**Run the whole local gate first — before opening a PR, and before anything that
costs money:**

```text
scripts/local_gate.sh
```

One command, ordered by cost, stops at the first failure: structural gates (image
tags, port registry, tracked secrets, Helm fail-closed guards) → the lint lane and
`bazel test //...` → the ADR-MCPRE-051 §7 SLO lane. Add `--with-kind` to also run the
fleet proofs on a local kind cluster before any cloud run.

`bazel test //...` alone is **not** the full battery: it excludes the `manual`-tagged
infra lane. The gate script runs each lane that CI runs.

Read [`docs/dev/local-gate-order.md`](docs/dev/local-gate-order.md) for what each
stage catches and the two ways the SLO lane can silently measure nothing. Use the
repository-specific MCP-RE conformance guide when available.

## Toolchain

The production Rust compiler is the first `rust.toolchain` version in `MODULE.bazel`
(1.99.1). Bazel supplies it hermetically, with the cargo, rustfmt and clippy of the same
release, so nothing on a developer machine selects the compiler: `bazel build
--config=lint //...` and `bazel build --config=rustfmt //...` use it, and a locally
installed `rustc` is not part of any build path.

Two other compilers exist on purpose. The Verus prover runs on that same toolchain's
`librustc_driver`, so its release in `verification/policy/toolchains.lock.toml` must declare
the same Rust channel. The Charon/Aeneas extraction lane uses one pinned nightly
(`nightly/…` in `MODULE.bazel`, `[charon].rust_toolchain` in the lock), selected only by
`--@rules_rust//rust/toolchain/channel=nightly`. `scripts/toolchain_consistency_gate.py`
fails when the production version, the lock, the Verus pins, the workflow job names or the
merge-readiness fallback disagree.

Moving the production compiler or the Verus release changes every unit fingerprint. That is
the intended invalidation: proof, test and mutation evidence is re-established on the new
revision and the affected reviews are re-attested.
