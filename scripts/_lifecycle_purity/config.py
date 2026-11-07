# SPDX-License-Identifier: Apache-2.0
"""The machines the gate holds, the standard-library paths they may use, and the syntax it reads."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "verification"))

#: The state machines that are values. Each depends on no production module, so "is this
#: transition legal?" cannot answer differently on two calls with the same arguments.
TARGETS = (
    REPO_ROOT / "mcp-re-proxy" / "src" / "runtime_state.rs",
    REPO_ROOT / "mcp-re-proxy" / "src" / "exchange_state.rs",
)

#: Standard-library paths the relation may depend on, each with the reason it cannot
#: introduce behaviour. Adding an entry is a deliberate edit, which is the point.
ALLOWED_STD_PATHS = {
    # Rendering `InvalidTransition` for an error message. Formatting traits carry no
    # state and make no decision.
    "std::fmt",
}

#: A `use` declaration anywhere on a line, including `pub use` and one inside a body.
USE_DECL = re.compile(r"(?:^\s*|[{;]\s*)(?:pub(?:\s*\([^)]*\))?\s+)?use\s+(?P<path>[^;]+);")

#: A name this file declares. Types and enum variants both matter: the transition match
#: writes `RuntimeState::Configured`, so `RuntimeState` must count as local.
LOCAL_DECL = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:enum|struct|type|trait)\s+(?P<name>\w+)"
)

#: The root segment of any `::`-qualified path.
PATH_ROOT = re.compile(r"(?<![:\w])(?P<root>\w+)::")

#: An out-of-line child module the file declares (`mod name;`). Its items are inside the
#: module tree, so a path into it is local; the child's own file is then held to this same
#: rule by the gate's verdict, so a child cannot import what its parent may not.
CHILD_MOD = re.compile(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<name>\w+)\s*;")
