"""Implementation of `scripts/unit_closure_gate.py`; the script is the entry point.

Importing the package puts `scripts/` and `tools/verification/` on `sys.path`, so every
submodule can import the shared owners (`_ratchet`, `_module_tree`, `_rust_source`,
`_manifest`) whichever order it is loaded in.
"""

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "scripts"))
sys.path.insert(0, str(_REPO / "tools" / "verification"))
