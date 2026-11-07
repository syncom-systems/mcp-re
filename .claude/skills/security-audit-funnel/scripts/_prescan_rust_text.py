"""Text helpers for Rust sources: test-gate blanking, const-eval masking and
offset-to-line lookups. Every blanking keeps newlines so line numbers stay true."""

from _prescan_vocab import RS_CONST_BLOCK, RS_FN, RS_TEST_ATTR


_BRACE_DELTA = {"{": 1, "}": -1}


def _matching_brace(src, brace):
    """Index of the `}` closing the `{` at ``brace``, or ``len(src)`` if unclosed."""
    depth = 0
    for i in range(brace, len(src)):
        depth += _BRACE_DELTA.get(src[i], 0)
        if depth == 0:
            return i
    return len(src)


def _blank(out, start, stop):
    for k in range(start, stop):
        if out[k] != "\n":
            out[k] = " "


def _is_bodyless(brace, semi):
    return brace == -1 or (semi != -1 and semi < brace)


def _item_end(src, after_attr):
    """End offset of the item that follows an attribute ending at ``after_attr``:
    its matching `}`, or its `;` when the item has no body."""
    brace = src.find("{", after_attr)
    semi = src.find(";", after_attr)
    if _is_bodyless(brace, semi):
        return semi + 1 if semi != -1 else len(src)
    return min(_matching_brace(src, brace) + 1, len(src))


def rust_prod_slice(src):
    """The production text of a .rs file: every test-gated ITEM blanked out.

    An item is test-gated when `#[cfg(test)]` or `#[cfg(all(test, ...))]` stands on
    it — the whole `mod tests` at the end, and equally an indented test-only helper
    inside an `impl`. Each is blanked from its attribute to the end of the item (its
    matching `}`, or its `;`), keeping newlines, so line numbers stay true and code
    AFTER a test helper is still scanned. Cutting at the first such attribute instead
    hid every production line below an indented helper; recognising only
    `#[cfg(test)]` scanned every `cfg(all(test, unix))` module as production.
    `cfg(not(test))` and `cfg(any(test, ..))` are not test-gated and stay.
    """
    out = list(src)
    for m in RS_TEST_ATTR.finditer(src):
        _blank(out, m.start(), _item_end(src, m.end()))
    return "".join(out)


def mask_const_eval(src):
    out = list(src)
    for m in RS_CONST_BLOCK.finditer(src):
        end = _matching_brace(src, m.end() - 1)
        _blank(out, m.end(), min(end, len(src)))
    return "".join(out)


def line_of(src, idx):
    return src.count("\n", 0, idx) + 1


def line_text(src, idx):
    start = src.rfind("\n", 0, idx) + 1
    end = src.find("\n", idx)
    return src[start: end if end != -1 else len(src)]


def enclosing_fn(src, idx):
    last = None
    for m in RS_FN.finditer(src, 0, idx):
        last = m.group(1)
    return last or "<fn>"
