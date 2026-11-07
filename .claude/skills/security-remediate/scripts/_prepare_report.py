"""The five sections `prepare` prints, each as a list of lines."""
from __future__ import annotations

from _prepare_anchors import locate
from _prepare_rust import component_root, module_size, rust_crate, rust_inline_tests, rust_module
from _prepare_symbols import defined_symbols, prioritise
from _prepare_tests import owning_build, test_candidates
from _prepare_usage import top_package, usages


def _note_line(note: str, max_note: int) -> str:
    # A prior adjudication or ruling can run to pages and is repeated on
    # every sibling finding; the head carries the decision, the ledger
    # carries the rest.
    tail = (" … (TRUNCATED at %d of %d chars — `file_findings.py` has it all)"
            % (max_note, len(note)) if len(note) > max_note else "")
    return "- prior notes: %s%s" % (note[:max_note], tail)


def _finding_lines(f: dict, max_note: int) -> list[str]:
    out = ["", "### %s  [%s/%s]  %s  status=%s" % (f["id"], f.get("severity"), f.get("category"),
                                                   f.get("title"), f.get("status"))]
    for k in ("claim", "impact", "suggested_remediation", "confidence", "lens", "reported_by"):
        if f.get(k):
            out.append("- %s: %s" % (k, f[k]))
    if f.get("notes"):
        out.append(_note_line(str(f["notes"]), max_note))
    if f.get("evidence_anchor"):
        out.append("- evidence (verbatim, from the audit pin):")
        out += ["    " + ln for ln in str(f["evidence_anchor"]).splitlines()]
    return out


def header(path: str, joined: dict) -> list[str]:
    return ["# PREPARE %s" % path,
            "findings: %d actionable   packet_found: %s   liveness: %s"
            % (joined["n"], joined["packet_found"], joined.get("liveness")), ""]


def findings_section(findings: list[dict], max_note: int) -> list[str]:
    out = ["## 1. Findings (critical -> low)"]
    for f in findings:
        out += _finding_lines(f, max_note)
    return out


def anchors_section(findings: list[dict], lines: list[str]) -> list[str]:
    out = ["", "## 2. Anchors in the CURRENT source (line numbers from the audit pin drift; these do not)"]
    for f in findings:
        loc = locate(f.get("evidence_anchor"), lines)
        where = (" at L" + ",".join(map(str, loc["lines"]))) if loc.get("lines") else ""
        out.append("- %s: %s%s%s" % (f["id"], loc["state"], where,
                                     ("  — " + loc["detail"]) if loc.get("detail") else ""))
    return out


def _rust_build_lines(path: str, src: str) -> list[str]:
    import rust_gate  # noqa: PLC0415
    compiled_by = rust_gate.compiling_targets([path])
    out = ["- crate: %s   in-file #[test] fns: %d" % (rust_crate(path) or "NONE FOUND",
                                                      rust_inline_tests(src)),
           "- Bazel targets compiling it: %s" % (", ".join(compiled_by) or "NONE FOUND"),
           "- unit-test targets: %s" % (", ".join(rust_gate.unit_test_targets(compiled_by))
                                        or "NONE FOUND")]
    size = module_size(path, src)
    if size:
        out.append("- module size: " + size)
    return out


def build_section(path: str, src: str) -> list[str]:
    out = ["", "## 3. Build and tests",
           "- owning BUILD.bazel: %s" % (owning_build(path) or "NONE FOUND")]
    if path.endswith(".rs"):
        out += _rust_build_lines(path, src)
    out.append("- component root: %s   (bazel tree //%s/...)" % (component_root(path),
                                                                 component_root(path)))
    tests = test_candidates(path)
    out.append("- %s: %s" % ("integration tests naming this module" if path.endswith(".rs")
                             else "test modules whose name contains the file stem",
                             ", ".join(tests) if tests else
                             "NONE — a behaviour-changing fix needs one created"))
    return out


def _usage_heading(path: str, lang_globs: list[str]) -> str:
    return ("## 4. Usage map — tracked %s files that import each name from `%s` (reach: no "
            "string-keyed factories, no getattr, no `import pkg` + attribute access, no untracked "
            "files%s)" % ("/".join(lang_globs),
                          rust_module(path) if path.endswith(".rs") else top_package(path) or "?",
                          "" if path.endswith(".py") else
                          "; Rust: a file counts only if it sits beside this one or spells the module "
                          "in a path — text sites, an approximation of name resolution"))


def _symbol_lines(sym: str, path: str, lang_globs: list[str], max_sites: int) -> list[str]:
    u = usages(sym, path, lang_globs, max_sites)
    if "error" in u:
        return ["- %s: ERROR %s" % (sym, u["error"])]
    c = u["prod"]
    out = ["- %s: prod import=%d construct=%d subclass=%d ref=%d | tests=%d"
           % (sym, c["import"], c["construct"], c["subclass"], c["ref"], u["tests"])]
    out += ["    " + site for site in u["sites"]]
    if u["truncated"]:
        out.append("    (TRUNCATED: %d of %d production sites shown)" % (max_sites, u["total_prod_sites"]))
    return out


def usage_section(a, src: str, findings: list[dict]) -> list[str]:
    path = a.file
    lang_globs = ["*.py"] if path.endswith(".py") else ["*.rs"] if path.endswith(".rs") else ["*"]
    syms = prioritise(defined_symbols(path, src), findings)
    out = ["", _usage_heading(path, lang_globs)]
    if len(syms) > a.max_symbols:
        out.append("(TRUNCATED: %d of %d symbols shown — finding-named symbols first)"
                   % (a.max_symbols, len(syms)))
    if not syms:
        out.append("- no top-level public symbols")
    for s in syms[:a.max_symbols]:
        out += _symbol_lines(s, path, lang_globs, a.max_sites)
    return out


def source_section(path: str, lines: list[str], max_lines: int) -> list[str]:
    shown = lines[:max_lines]
    out = ["", "## 5. Source — %s (%d lines%s)" % (path, len(lines),
                                                  ", TRUNCATED at %d: Read the rest" % max_lines
                                                  if len(lines) > max_lines else "")]
    width = len(str(len(shown)))
    out += ["%*d  %s" % (width, i, ln) for i, ln in enumerate(shown, 1)]
    return out
