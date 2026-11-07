# SPDX-License-Identifier: Apache-2.0
"""Implementation of `scripts/module_size_gate.py`, split by responsibility.

`config` holds the register's vocabulary, `measure` the per-file ratchet, `growth` the
one-shot upward-baseline rule, `emit` the registry printer, `selftest*` the gate's own
proof and `cli` the entry point. The entry script re-exports the public names.
"""
