"""
Mechanical fixedness detector — RAW TEXT ONLY (no corpus metadata, no model).
Given (canonical idiom form, sentence), align and classify the surface form:
  identical | inflection | det-change | det-insert | det-delete |
  insertion | notfound | other
Pure string/suffix operations. The high-precision literal branch (per MAGPIE
metadata analysis) = {det-change, det-insert, insertion}.
"""
import re

DETS = {"the","a","an"}
SUFFIXES = ["ings","ing","edly","ed","es","s","d"]

def toks(t): return re.findall(r"[a-zA-Z']+", t.lower())

def stem(w):
    for s in SUFFIXES:
        if w.endswith(s) and len(w)-len(s) >= 3:
            return w[:-len(s)]
    return w

def match(a, b):
    """exact / stem match between two tokens."""
    if a == b: return "exact"
    if stem(a) == stem(b): return "stem"
    return None

def classify(canonical: str, sentence: str) -> str:
    c = toks(canonical); s = toks(sentence)
    c_content = [(i,w) for i,w in enumerate(c) if w not in DETS]
    if not c_content: return "other"
    # greedy in-order alignment of canonical CONTENT tokens in the sentence
    pos = []; j = 0
    for _, w in c_content:
        found = None
        for k in range(j, len(s)):
            if match(w, s[k]): found = k; break
        if found is None: return "notfound"
        pos.append(found); j = found + 1
    lo, hi = pos[0], pos[-1]
    window = s[lo:hi+1]
    # inflection: any content token matched by stem only
    inflected = any(match(w, s[k]) == "stem" for (_, w), k in zip(c_content, pos))
    # determiners inside the canonical idiom vs inside the matched window
    c_dets = [w for w in c if w in DETS]
    w_dets = [w for w in window if w in DETS]
    # non-determiner insertions: window tokens that are neither matched content
    # positions nor determiners
    matched_set = set(pos)
    inserted = [w for k, w in enumerate(window, start=lo)
                if k not in matched_set and w not in DETS]
    if not inserted:
        if c_dets == w_dets:
            return "inflection" if inflected else "identical"
        if len(w_dets) > len(c_dets):  return "det-insert"
        if len(w_dets) < len(c_dets):  return "det-delete"
        return "det-change"           # same count, different determiner
    return "insertion"

LITERAL_BRANCH = {"det-change", "det-insert", "insertion"}

def predict(canonical: str, sentence: str):
    """returns ('l', cls) on the high-precision literal branch, else (None, cls)
    = abstain (Xvay-style: speak only where the signal is strong)."""
    cls = classify(canonical, sentence)
    return ("l" if cls in LITERAL_BRANCH else None), cls
