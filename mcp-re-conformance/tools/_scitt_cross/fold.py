# SPDX-License-Identifier: Apache-2.0
"""RFC 9162 inclusion-proof verification, transcribed from the RFC text."""

from __future__ import annotations

import hashlib


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _sibling_is_left(fnode: int, snode: int) -> bool:
    """`fn` is a right child, or the right-edge promotion case `fn == sn`."""
    return fnode % 2 == 1 or fnode == snode


def _skip_even_levels(fnode: int, snode: int) -> tuple[int, int]:
    while fnode != 0 and fnode % 2 == 0:
        fnode //= 2
        snode //= 2
    return fnode, snode


def _fold_step(root: bytes, fnode: int, snode: int, sibling: bytes) -> tuple[bytes, int, int]:
    if snode == 0:
        raise ValueError("inclusion path longer than the tree admits")
    if _sibling_is_left(fnode, snode):
        root = _node_hash(sibling, root)
        fnode, snode = _skip_even_levels(fnode, snode)
    else:
        root = _node_hash(root, sibling)
    return root, fnode // 2, snode // 2


def fold_rfc9162(leaf_bytes: bytes, tree_size: int, leaf_index: int, path: list) -> bytes:
    """RFC 9162 §2.1.3.2 inclusion-proof verification, transcribed from the RFC text.

    Both `fn` and `sn` are tracked, and `sn == 0` is required at the end. That is what
    binds the path LENGTH, the leaf index and the tree size: an index-bit walk that
    only shifts right consults the low bits of the index and nothing else, so a
    receipt's claimed position and log size stay unconstrained even though both ride
    in the UNSIGNED `vdp` header. It is also the only version that gets a
    non-power-of-two tree right, because `fn == sn` is the right-edge promotion case.
    """
    if leaf_index >= tree_size:
        raise ValueError("leaf_index >= tree_size")
    fnode, snode = leaf_index, tree_size - 1
    root = hashlib.sha256(b"\x00" + leaf_bytes).digest()
    for sibling in path:
        root, fnode, snode = _fold_step(root, fnode, snode, sibling)
    if snode != 0:
        raise ValueError("inclusion path shorter than the tree requires")
    return root
