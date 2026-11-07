# SPDX-License-Identifier: Apache-2.0
"""The mutated workflow texts the selftest feeds the gate, each with the failure it must produce."""

from __future__ import annotations

Texts = dict[str, str]
Control = tuple[str, Texts, str]

VERIFICATION_ON = "on:\n  schedule:"


def mutate(texts: Texts, name: str, old: str, new: str) -> Texts:
    assert old in texts[name], f"selftest anchor missing in {name}: {old!r}"
    return {**texts, name: texts[name].replace(old, new, 1)}


def _pull_request_on(path: str) -> str:
    return f'on:\n  pull_request:\n    paths:\n      - "{path}"\n  schedule:'


def complete_run_trigger_controls(texts: Texts) -> list[Control]:
    def verification(new: str) -> Texts:
        return mutate(texts, "verification.yml", VERIFICATION_ON, new)

    return [
        ("a pull_request on MODULE.bazel starts the complete run",
         verification(_pull_request_on("MODULE.bazel")),
         "MODULE.bazel starts the complete run"),
        ("a pull_request on the toolchain pin starts the complete run",
         verification(_pull_request_on("verification/policy/toolchains.lock.toml")),
         "toolchains.lock.toml starts the complete run"),
        ("a pull_request on the verification platform starts the complete run",
         verification(_pull_request_on("tools/verification/**")),
         "tools/verification/verify starts the complete run"),
        ("an unfiltered push starts the complete run",
         verification("on:\n  push:\n  schedule:"),
         "declares ['push']"),
        ("workflow_run chains the complete run",
         verification("on:\n  workflow_run:\n    workflows: [pre-merge]\n  schedule:"),
         "declares ['workflow_run']"),
        ("the schedule is removed",
         mutate(texts, "verification.yml", '  schedule:\n    - cron: "0 4 * * 0"\n', ""),
         "no longer declares ['schedule']"),
    ]


def complete_run_body_controls(texts: Texts) -> list[Control]:
    select_units = "python3 tools/verification/select-units --base HEAD^1 --out u; echo \"complete run:"
    return [
        ("the scope job stops refusing foreign events",
         mutate(texts, "verification.yml", "exit 1 ;;", "exit 0 ;;"),
         "does not refuse every event"),
        ("a select-units scope returns to the complete run",
         mutate(texts, "verification.yml", "echo \"complete run:", select_units),
         "invokes `select-units`"),
        ("the aggregate gate is dropped",
         mutate(texts, "verification.yml", "./tools/verification/verify --aggregate --gate", "./tools/verification/verify --aggregate"),
         "step that reports a missing record as INCOMPLETE is gone"),
        ("another workflow calls the complete run",
         {**texts, "post-merge.yml": texts["post-merge.yml"] + "  full:\n    uses: ./.github/workflows/verification.yml\n"},
         "calls verification.yml"),
        ("another workflow dispatches it",
         mutate(texts, "pre-merge.yml", "    steps:\n", "    steps:\n      - run: gh workflow run verification.yml\n"),
         "dispatches a workflow"),
    ]


def probe_controls(texts: Texts) -> list[Control]:
    def probe(old: str, new: str) -> Texts:
        return mutate(texts, "mutation-probe.yml", old, new)

    return [
        ("the probe returns to push",
         probe("on:\n  pull_request:", "on:\n  push:\n    branches: [main]\n  pull_request:"),
         "declares ['push']"),
        ("the probe loses its timeout",
         probe("timeout-minutes: 30", "timeout-minutes: 360"),
         "timeout-minutes '360'"),
        ("the probe job runs even when the scope deferred",
         probe("    if: needs.scope.outputs.measure == 'true'\n", ""),
         "does not run only when `scope` decided to measure"),
        ("the probe loses its unit cap",
         probe("--max-units 20 ", ""),
         "--max-units"),
        ("the probe stops deferring when scoping fails",
         probe("if ! python3 tools/verification/select-units", "python3 tools/verification/select-units"),
         "does not defer"),
        ("the probe reinstalls a floating toolchain",
         probe("      - name: Mutation-lane self-tests", "      - run: rustup toolchain install stable\n      - name: Mutation-lane self-tests"),
         "installs or selects a toolchain"),
    ]


def merge_path_controls(texts: Texts) -> list[Control]:
    return [
        ("pre-merge gains a path filter",
         mutate(texts, "pre-merge.yml", "on:\n  pull_request:\n", 'on:\n  pull_request:\n    paths:\n      - "mcp-re-core/**"\n'),
         "EVERY pull request"),
        ("post-merge stops calling pre-merge",
         mutate(texts, "post-merge.yml", "uses: ./.github/workflows/pre-merge.yml", "uses: ./.github/workflows/weekly.yml"),
         "does not call ./.github/workflows/pre-merge.yml"),
    ]


def all_controls(texts: Texts) -> list[Control]:
    return (
        complete_run_trigger_controls(texts)
        + complete_run_body_controls(texts)
        + probe_controls(texts)
        + merge_path_controls(texts)
    )
