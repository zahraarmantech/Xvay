"""
XVay CANON — the single tokenizer. Every component that matches strings uses
THIS and nothing else.

Why it exists: XVay previously normalised strings in five places with five
different separator lists. Two exploitable bugs came from that directly
(a resource name with '_' never matched; quoting hid a destructive verb).
Maintaining separator lists is a bug factory: whatever you forget is a bypass.

Rule here: anything that is not a letter or a digit is a separator. There is no
list to forget. Unicode letters are kept (a Persian filename is still a word),
but Latin-lookalike scripts are handled by arg_check, not here.

This module decides nothing. It only tokenizes.
"""
import unicodedata

def tokens(s):
    """Canonical token list: lowercase, any non-alphanumeric is a separator."""
    if not isinstance(s, str): s = str(s)
    s = unicodedata.normalize("NFKC", s)      # collapse compatibility forms
    # Invisible FORMAT characters (zero-width space/joiner, BOM, bidi marks)
    # have no meaning inside a command; their only use here is to split a verb
    # so it stops matching. Remove them before tokenizing.
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")
    out, buf = [], []
    for ch in s.lower():
        if ch.isalnum():
            buf.append(ch)
        elif buf:
            out.append("".join(buf)); buf = []
    if buf: out.append("".join(buf))
    return out

def canon(s):
    """Canonical string form: tokens joined by single spaces."""
    return " ".join(tokens(s))

def token_set(s):
    return set(tokens(s))

def contains_phrase(haystack, needle):
    """True if EVERY token of `needle` appears in `haystack` (order-free).
    Used for resource / tool-name matching so that 'orders-primary',
    'orders_primary' and 'Orders Primary' all behave identically."""
    h = token_set(haystack)
    n = tokens(needle)
    return bool(n) and all(t in h for t in n)
