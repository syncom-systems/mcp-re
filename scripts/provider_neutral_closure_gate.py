#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral closure gate — the local gate may not reach a cloud.

THE RULE. The execution closure of `scripts/local_gate.sh --with-kind` is provider-neutral:
no AWS, GCP or Azure CLI, no provider account, project or registry discovery, and no cloud
credential. Provider provisioning lives in drivers the local path does not reach.

THE FAILURE IT EXISTS FOR. The fleet harness ran `gcloud config get-value project` for every
substrate, kind included, behind `|| true`. A PATH tripwire caught it at run time, which is a
second control and stays one. Putting the line behind `if PROVIDER=gke` would have made the
symptom go away and left the design as it was: one script holding provisioning AND proofs,
where the next provider line is one edit away from the local path. So the harness was split
(docs/security/fleet-proofs-core.sh, -kind.sh, gke-multi-replica-validation.sh), and this
gate is what keeps the split true.

WHAT IT READS. The closure is every repository script reachable from `scripts/local_gate.sh`
by invocation, followed through shell scripts (any repository path in a command segment that
is not a message — `echo`, `printf`, `log`, `fail`, `verdict` — counts, whether in command
position or as an argument to `bash`, `python3`, `exec`, `timeout` and the like) and through
Python files (paths passed to `subprocess`/`os` process calls, and modules imported from the
directories this repository's scripts import from). Comments are never callers.

Over-approximating the closure is the safe direction for a prohibition: an extra file scanned
can only produce a refusal, never a pass. The required-members check is the other direction:
the files that MUST be in the closure (the kind driver, the proof core, the Job-spec
rehearsal) are asserted present, so a parse change cannot shrink the closure into a vacuous
pass, and the cloud driver is asserted absent.

WHAT IT REFUSES, inside that closure:
  * a provider CLI in command position (also after `$(`, a backtick, `exec`, `command`,
    `env`, `xargs`, `timeout N`, `if`/`then`/`!` …) or probed with `command -v`/`which`/`type`,
    and a provider CLI as a quoted literal (a `subprocess` argv inside a heredoc);
  * in Python: a provider CLI as the program of a process call or `shutil.which`, an import
    of a cloud SDK, a credential environment read;
  * a cloud credential variable, and a provider registry host, in shell code.
A guard does not exempt anything: a provider call behind `if [[ $PROVIDER == gke ]]` in a
closure file is still in the closure.

WHAT IT DOES NOT PROVE. What a `bazel run`/`bazel test` target does at run time — Rust is
opaque to a text gate. The runtime PATH tripwires are the independent control for that.

Run:  python3 scripts/provider_neutral_closure_gate.py
      python3 scripts/provider_neutral_closure_gate.py --selftest
"""

from __future__ import annotations

import ast
import re
import sys
from collections import deque
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENTRY = "scripts/local_gate.sh"

PROVIDER_CLIS = frozenset(
    {"gcloud", "gsutil", "bq", "aws", "eksctl", "az", "azd", "terraform", "tofu", "pulumi", "lightsail"}
)
CREDENTIAL_VARS = re.compile(
    r"\b(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_PROFILE|AWS_WEB_IDENTITY_TOKEN_FILE"
    r"|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CLOUD_PROJECT|CLOUDSDK_[A-Z_]+|AZURE_[A-Z_]+"
    r"|MCP_RE_GCP_ACCESS_TOKEN|MCP_RE_AWS_KMS_ROLE_ARN|MCP_RE_GCP_KMS_GSA|ECR_REGISTRY)\b"
)
REGISTRY_HOSTS = re.compile(r"\.dkr\.ecr\.|docker\.pkg\.dev|(?<![\w.-])gcr\.io|azurecr\.io|amazonaws\.com")
CLOUD_SDK_MODULES = ("boto3", "botocore", "google.cloud", "google.auth", "azure")

#: Files that must be in the closure, and the one that must not.
REQUIRED_MEMBERS = (
    "docs/security/fleet-proofs-kind.sh",
    "docs/security/fleet-proofs-core.sh",
    "tools/slo/rehearse_job_spec.sh",
    "tools/slo/run_slo_job.sh",
)
FORBIDDEN_MEMBERS = ("docs/security/gke-multi-replica-validation.sh", "tools/slo/run_slo_job_cloud.sh")

#: Directories a closure Python file's bare `import x` may resolve into.
PY_IMPORT_DIRS = ("scripts", "scripts/lib", "tools/slo", "tools/verification", "docs/security")

REPO_PATH = re.compile(r"(?<![\w.-])((?:scripts|tools|docs)/[A-Za-z0-9_./-]*[A-Za-z0-9_-])")
#: The repository's inline-comment idiom inside a `&&` chain: `` `# …` ``.
BACKTICK_COMMENT = re.compile(r"`#[^`]*`")
MESSAGE_WORDS = {"echo", "printf", "log", "fail", "verdict", "warn", "die"}
PREFIX_WORDS = {
    "exec", "command", "env", "sudo", "time", "nohup", "xargs", "!", "if", "then", "else", "elif",
    "do", "while", "until", "builtin", "eval", "bash", "sh", "-c", "-e", "-x", "-lc",
}
PROBE_WORDS = {"which", "type", "hash"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _shell_code_lines(text: str) -> list[str]:
    lines = []
    for line in BACKTICK_COMMENT.sub(" ", text).splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # A trailing ` # comment` (whitespace before the hash) is a comment too.
        lines.append(re.sub(r"\s#\s.*$", "", line))
    return lines


def _segments(line: str) -> list[list[str]]:
    """Command segments of one shell line, as word lists, quote-aware.

    A single-quoted string is one opaque word. A double-quoted string is one word too,
    except that a `$( … )` or backtick substitution inside it is code and is split into
    segments of its own — `X="$(gcloud config get-value project)"` is a gcloud invocation.
    Unquoted `&& || ; | ( ) { } $(` and backticks end a segment.
    """
    segments: list[list[str]] = [[]]
    word: list[str] = []
    nested: list[str] = []

    def end_word() -> None:
        if word:
            segments[-1].append("".join(word))
            word.clear()

    def end_segment() -> None:
        end_word()
        segments.append([])

    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == "'":
            j = line.find("'", i + 1)
            j = n if j < 0 else j
            word.append(line[i + 1:j])
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and line[j] != '"':
                if line[j] == "\\":
                    j += 2
                    continue
                if line.startswith("$(", j) or line[j] == "`":
                    close = ")" if line[j] == "$" else "`"
                    start = j + (2 if close == ")" else 1)
                    depth, k = 1, start
                    while k < n and depth:
                        if close == ")" and line[k] == "(":
                            depth += 1
                        elif line[k] == close:
                            depth -= 1
                        k += 1
                    nested.append(line[start:k - 1])
                    j = k
                    continue
                j += 1
            word.append(line[i + 1:j])
            i = j + 1
        elif line.startswith(("&&", "||"), i):
            end_segment()
            i += 2
        elif line.startswith("$(", i):
            end_segment()
            i += 2
        elif c in ";|(){}`":
            end_segment()
            i += 1
        elif c.isspace():
            end_word()
            i += 1
        else:
            word.append(c)
            i += 1
    end_word()
    out = [seg for seg in segments if seg]
    for inner in nested:
        out.extend(_segments(inner))
    return out


def _command_word(words: list[str]) -> tuple[str | None, list[str]]:
    i = 0
    while i < len(words):
        w = words[i]
        if ASSIGNMENT.match(w) or w in PREFIX_WORDS:
            i += 1
        elif w == "timeout" and i + 1 < len(words):
            i += 2
        else:
            return w, words[i + 1:]
    return None, []


def _normalize(token: str, repo_files: set[str]) -> str | None:
    match = REPO_PATH.search(token.strip("\"'"))
    if match and match.group(1) in repo_files:
        return match.group(1)
    return None


def shell_findings_and_edges(text: str, repo_files: set[str]) -> tuple[list[str], set[str]]:
    findings: list[str] = []
    edges: set[str] = set()
    for line in _shell_code_lines(text):
        for m in re.finditer(r"[\"']([a-z]+)[\"']", line):
            if m.group(1) in PROVIDER_CLIS:
                findings.append(f"provider CLI as a quoted literal ({m.group(1)!r}): {line.strip()}")
        if CREDENTIAL_VARS.search(line):
            findings.append(f"cloud credential/account variable: {line.strip()}")
        if REGISTRY_HOSTS.search(line):
            findings.append(f"provider registry host: {line.strip()}")
        for words in _segments(line):
            command, args = _command_word(words)
            if command is None:
                continue
            base = command.rsplit("/", 1)[-1]
            if base in PROVIDER_CLIS:
                findings.append(f"provider CLI invoked ({base}): {line.strip()}")
            for i, word in enumerate(words[:-1]):
                probe = word in PROBE_WORDS or (word == "command" and words[i + 1] in {"-v", "-V"})
                if probe and any(w in PROVIDER_CLIS for w in words[i + 1:]):
                    findings.append(f"provider CLI probed: {line.strip()}")
                    break
            if command in MESSAGE_WORDS:
                continue
            for word in [command, *args]:
                found = _normalize(word, repo_files)
                if found:
                    edges.add(found)
    return findings, edges


def _is_process_call(func: ast.expr) -> bool:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id in {"subprocess", "os", "shutil"}
    return isinstance(func, ast.Name) and func.id in {"run", "check_call", "check_output", "Popen", "call"}


def _strings(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def python_findings_and_edges(text: str, path: str, repo_files: set[str]) -> tuple[list[str], set[str]]:
    findings: list[str] = []
    edges: set[str] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [f"cannot parse as Python ({exc.msg}); a closure file this gate cannot read is not neutral"], edges
    here = str(Path(path).parent)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                if any(name == m or name.startswith(m + ".") for m in CLOUD_SDK_MODULES):
                    findings.append(f"cloud SDK import ({name})")
                for base in (here, *PY_IMPORT_DIRS):
                    candidate = f"{base}/{name.replace('.', '/')}.py"
                    if candidate in repo_files:
                        edges.add(candidate)
        if isinstance(node, ast.Call) and _is_process_call(node.func):
            values = _strings(node)
            first = values[0].split()[0] if values and values[0].split() else ""
            if first.rsplit("/", 1)[-1] in PROVIDER_CLIS:
                findings.append(f"provider CLI as a process ({first}) at line {node.lineno}")
            for value in values:
                found = _normalize(value, repo_files)
                if found:
                    edges.add(found)
        if isinstance(node, ast.Call):
            for value in _strings(node):
                if CREDENTIAL_VARS.fullmatch(value) and _reads_environment(node):
                    findings.append(f"cloud credential read ({value}) at line {node.lineno}")
        if isinstance(node, ast.Subscript) and _is_environ(node.value):
            for value in _strings(node.slice):
                if CREDENTIAL_VARS.fullmatch(value):
                    findings.append(f"cloud credential read ({value}) at line {node.lineno}")
    return findings, edges


def _is_environ(node: ast.expr) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "environ"


def _reads_environment(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "getenv":
        return True
    return isinstance(func, ast.Attribute) and func.attr == "get" and _is_environ(func.value)


def _kind(path: str, text: str) -> str:
    if path.endswith(".py"):
        return "py"
    if path.endswith(".sh"):
        return "sh"
    first = text.split("\n", 1)[0]
    if first.startswith("#!") and "python" in first:
        return "py"
    if first.startswith("#!") and ("bash" in first or first.endswith("sh")):
        return "sh"
    return "other"


def analyse(read: dict[str, str], entry: str) -> tuple[set[str], dict[str, list[str]]]:
    repo_files = set(read)
    seen = {entry}
    queue = deque([entry])
    findings: dict[str, list[str]] = {}
    while queue:
        current = queue.popleft()
        text = read.get(current, "")
        kind = _kind(current, text)
        if kind == "sh":
            hits, edges = shell_findings_and_edges(text, repo_files)
        elif kind == "py":
            hits, edges = python_findings_and_edges(text, current, repo_files)
        else:
            hits, edges = [], set()
        if hits:
            findings[current] = hits
        for found in sorted(edges - seen):
            seen.add(found)
            queue.append(found)
    return seen, findings


def _read_repo() -> dict[str, str]:
    read: dict[str, str] = {}
    for top in ("scripts", "tools", "docs"):
        for path in (REPO / top).rglob("*"):
            if path.is_file() and path.suffix in {"", ".py", ".sh"} and "__pycache__" not in path.parts:
                read[path.relative_to(REPO).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
    return read


def adjudicate(read: dict[str, str], entry: str = ENTRY) -> tuple[set[str], list[str]]:
    closure, findings = analyse(read, entry)
    problems = [f"{path}: {hit}" for path, hits in sorted(findings.items()) for hit in hits]
    problems += [f"{m}: REQUIRED in the local closure and not reached" for m in REQUIRED_MEMBERS
                 if m in read and m not in closure]
    problems += [f"{m}: REQUIRED in the local closure and does not exist" for m in REQUIRED_MEMBERS if m not in read]
    problems += [f"{m}: a cloud driver is reachable from {entry}" for m in FORBIDDEN_MEMBERS if m in closure]
    return closure, problems


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    closure, problems = adjudicate(_read_repo())
    for problem in problems:
        print(f"  ✗ {problem}")
    if problems:
        print(f"provider-neutral closure gate: FAILED ({len(problems)} finding(s) in the local execution closure)")
        return 1
    print(f"provider-neutral closure gate: OK — {len(closure)} script(s) reachable from {ENTRY}, "
          f"none invoking a provider CLI, credential or registry")
    return 0


def selftest() -> int:
    base = {
        ENTRY: "#!/bin/bash\nrun stage_kind\nstage_kind() {\n  docs/security/fleet-proofs-kind.sh || return $?\n"
               "  tools/slo/rehearse_job_spec.sh\n}\n",
        "docs/security/fleet-proofs-kind.sh": "#!/bin/bash\n"
            "printf 'cloud custody belongs to docs/security/gke-multi-replica-validation.sh\\n' >&2\n"
            "exec \"$REPO_ROOT/docs/security/fleet-proofs-core.sh\"\n",
        "docs/security/fleet-proofs-core.sh": "#!/bin/bash\n# gcloud is never called here\n"
            "echo 'run gcloud yourself'\nLOADGEN=\"$(kubectl get pod -o json | python3 \"$REPO_ROOT/docs/security/sel.py\")\"\n",
        "docs/security/sel.py": "import json\nTABLE = {'gcloud': 'a provider, as data'}\n",
        "tools/slo/rehearse_job_spec.sh": "#!/bin/bash\ntools/slo/run_slo_job.sh - kind-local 1 out.json\n",
        "tools/slo/run_slo_job.sh": "#!/bin/bash\nkubectl apply -f -\n",
        "docs/security/gke-multi-replica-validation.sh": "#!/bin/bash\ngcloud container clusters create x\n",
    }
    closure, problems = adjudicate(base)
    assert problems == [], problems
    assert "docs/security/sel.py" in closure and "docs/security/gke-multi-replica-validation.sh" not in closure

    def refused(path: str, text: str, needle: str) -> None:
        tree = dict(base)
        tree[path] = tree.get(path, "#!/bin/bash\n") + text
        _, found = adjudicate(tree)
        assert any(needle in p for p in found), (text, found)

    core = "docs/security/fleet-proofs-core.sh"
    # THE REGRESSION: the exact line the rehearsal hit, in the provider-neutral core.
    refused(core, 'PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"\n', "gcloud")
    # A guard does not exempt a provider call from the closure.
    refused(core, 'if [[ "$PROVIDER" == eks ]]; then aws sts get-caller-identity; fi\n', "aws")
    refused(core, "x=`eksctl get clusters`\n", "eksctl")
    refused(core, "command -v gcloud >/dev/null && echo yes\n", "probed")
    refused(core, "timeout 30 az account show\n", "az")
    refused(core, "python3 - <<'PY'\nimport subprocess; subprocess.run(['aws', 'sts'])\nPY\n", "quoted literal")
    refused(core, 'export K="$AWS_ACCESS_KEY_ID"\n', "credential")
    refused(core, 'IMG="123.dkr.ecr.eu-north-1.amazonaws.com/x:1"\n', "registry")
    # Transitively: a NEW script reached from the closure that calls a provider.
    tree = dict(base, **{"tools/new_helper.sh": "#!/bin/bash\naws ecr get-login-password\n"})
    tree[core] += '"$REPO_ROOT/tools/new_helper.sh" --flag\n'
    assert any(p.startswith("tools/new_helper.sh: provider CLI invoked") for p in adjudicate(tree)[1])
    # Python reached from the closure: a provider process, a cloud SDK, a credential read.
    for snippet, needle in (
        ("import subprocess\nsubprocess.run(['gcloud', 'auth', 'print-access-token'])\n", "process"),
        ("import shutil\nshutil.which('aws')\n", "process"),
        ("import boto3\n", "cloud SDK"),
        ("import os\nos.environ['GOOGLE_APPLICATION_CREDENTIALS']\n", "credential read"),
        ("import os\nos.environ.get('AWS_PROFILE')\n", "credential read"),
    ):
        tree = dict(base)
        tree["docs/security/sel.py"] = snippet
        assert any(needle in p for p in adjudicate(tree)[1]), snippet
    # Reaching the cloud driver is itself refused, even with no other finding.
    tree = dict(base)
    tree["docs/security/fleet-proofs-kind.sh"] += "docs/security/gke-multi-replica-validation.sh --teardown\n"
    assert any("cloud driver is reachable" in p for p in adjudicate(tree)[1])
    # A closure that lost a required member is not a pass.
    tree = dict(base)
    tree[ENTRY] = "#!/bin/bash\ntools/slo/rehearse_job_spec.sh\n"
    assert any("fleet-proofs-kind.sh: REQUIRED" in p for p in adjudicate(tree)[1])
    print("provider-neutral closure gate selftest: OK (injected provider calls refused; messages, comments "
          "and data tables are not callers)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
