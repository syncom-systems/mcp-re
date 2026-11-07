# SPDX-License-Identifier: Apache-2.0
"""How the proxy is started for the instruments, and what its startup transcript states."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from phases_context import STARTUP_LOG_ENV


def proxy_launcher(out_dir: Path, binary: Path, pool: int | None, isolation_plan: Path | None = None) -> Path:
    """The proxy as the instruments start it: an exec wrapper adding the pool flag.

    The rig and the bench take the proxy as ONE executable path and build its arguments
    themselves, so a flag can reach it only through a wrapper. `exec` keeps the proxy at the
    wrapper's pid and executable. Its stderr is copied to `$MCP_RE_CEILING_PROXY_LOG` up to
    and including the serving line, then forwarded by `cat` alone: after startup the stream
    is the per-request audit record, which this never parses or writes to disk.

    With an isolation plan, `isolation.py enforce` runs beside the proxy (same pid: `exec`)
    and places its threads per the plan, logging to `<startup log>.affinity.jsonl`."""
    wrapper = out_dir / f"{binary.name}.sh"
    flag = f" --replay-redis-pool-size {pool}" if pool is not None else ""
    default_log = shlex.quote(str(out_dir / "proxy-startup.log"))
    enforcer = ""
    if isolation_plan is not None:
        script = shlex.quote(str(Path(__file__).resolve().parent / "isolation.py"))
        enforcer = (f'python3 {script} enforce --pid $$ --plan {shlex.quote(str(isolation_plan))} '
                    '--log "${log%.log}.affinity.jsonl" </dev/null >/dev/null 2>&1 &\n')
    wrapper.write_text(
        "#!/bin/bash\n"
        f'log="${{{STARTUP_LOG_ENV}:-{default_log}}}"\n'
        + enforcer +
        f'exec {shlex.quote(str(binary))} "$@"{flag} 2> >(\n'
        "  while IFS= read -r line; do\n"
        "    printf '%s\\n' \"$line\" >&2\n"
        "    printf '%s\\n' \"$line\" >> \"$log\"\n"
        "    if [[ $line == *\"async fleet serving on \"* ]]; then exec cat >&2; fi\n"
        "  done)\n")
    wrapper.chmod(0o755)
    return wrapper


def startup_facts(log_path: Path) -> dict:
    """What each proxy launch logged in `log_path` stated about its replay store."""
    text = log_path.read_text(errors="replace") if log_path.is_file() else ""
    return {"launches": text.count("async fleet serving on "),
            "replay_pool": [int(n) for n in re.findall(r"replay redis pool = (\d+) connections", text)],
            "replay_tier": re.findall(r"replay-store backend=redis tier=(\S+)", text)}
