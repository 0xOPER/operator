#!/usr/bin/env python3
"""citations -- verify every quote in a report against its SAVED source.

Runs OFFLINE (the check jail has no network): the report's [n] citations name
URLs by their order in the sources dir's *.url files; each quoted passage
must appear verbatim in the matching *.body. A fabricated URL has no saved
copy; a fabricated quote isn't in its source's bytes; either leaves the row
red with the citation named.

The quote syntax is the report's own: a line starting with '>' followed by
'[n]' inside the surrounding text, or [n] after a quoted string. This check
takes the SIMPLE contract: every [n] marker in the report must have (a) a
saved source for the URL it refers to (same order as the URL list at the
end) and (b) the sentence IMMEDIATELY BEFORE the marker, when it is a
'>'-quoted line, present verbatim in that source. Claims without quotes pass
unchallenged -- the row's label is author-reachable and the matrix says so.

usage: citations.py <report.md> <sources-dir>
exit: 0 all checked quotes verify, 1 a citation fails, 2 usage
"""
import os
import re
import sys

CITE_RE = re.compile(r"\[(\d+)\]")
QUOTE_RE = re.compile(r"^\s*>\s*(.+?)\s*\[(\d+)\]\s*$", re.M)


def main(argv):
    structure_only = (len(argv) == 3 and argv[1] == "--structure-only")
    if len(argv) != 3:
        print("usage: citations.py <report.md> <sources-dir> | citations.py --structure-only <report.md>", file=sys.stderr)
        return 2
    report = argv[2] if structure_only else argv[1]
    src = None if structure_only else argv[2]
    if not os.path.isfile(report):
        print(f"citations: no report at {report}", file=sys.stderr)
        return 1
    text = open(report, encoding="utf-8", errors="replace").read()
    # the seal: only bodies the MANIFEST names are citable truth (a
    # hand-planted .url/.body pair certifies nothing -- the review planted
    # one and a fabricated quote verified against it)
    mp = os.path.join(src, "sources.manifest") if src else ""
    sealed = {}
    if mp and os.path.isfile(mp):
        for ln in open(mp, encoding="utf-8"):
            parts = ln.strip().split("\t")
            if len(parts) == 2:
                sealed[parts[0]] = parts[1]  # body-hash -> url
    import hashlib
    sources = {}
    for name in (os.listdir(src) if src and os.path.isdir(src) else []):
        if not name.endswith(".body"):
            continue
        body = open(os.path.join(src, name), "rb").read()
        h = hashlib.sha256(body).hexdigest()[:16]
        u = sealed.get(h)
        if u is not None:  # only sealed bodies are truth (whatever their name)
            sources[name] = (u, body)
    # the [n] -> URL map comes from the NUMBERED CLOSING LIST only (a URL in
    # prose is not a citation target -- the review made a decoy URL [1])
    listed = {int(m.group(1)): m.group(2) for m in re.finditer(
        r"^\s*(\d+)\.\s*(https?://[^\s]+)\s*$", text, re.M)}
    bad = []
    # a '>' quote line the regex can't parse (trailing punctuation, a
    # missing marker) is a HUMAN-VISIBLE QUOTE the machine didn't check --
    # refuse rather than silently skipping (the review slipped one past)
    for ln in text.splitlines():
        t = ln.strip()
        _qm = re.match(r"^>\s*(.+?)\s*\[(\d+)\]\s*$", ln)
        if t.startswith(">") and not _qm and "[" in t:
            bad.append(f"an unparseable quote line: {t[:60]!r}")
    if structure_only:
        cites = [int(m.group(1)) for m in CITE_RE.finditer(text)]
        if not text.strip() or not cites or not listed:
            bad.append("report must carry inline [n] citations and a closing numbered URL list")
        for n in cites:
            if n not in listed:
                bad.append(f"[{n}] has no URL at that position in the numbered list")
        for b in bad:
            print(f"citations: {b}", file=sys.stderr)
        if bad:
            return 1
        print(f"citations: structure verified ({len(cites)} citation(s), {len(listed)} listed URL(s))")
        return 0
    for m in QUOTE_RE.finditer(text):
        quote, n = m.group(1).strip(), int(m.group(2))
        want = listed.get(n)
        if want is None:
            bad.append(f"[{n}] has no URL at that position in the numbered list")
            continue
        hit = next((h for h, (u, _) in sources.items() if u == want), None)
        if hit is None:
            bad.append(f"[{n}] {want}: no saved source (fabricated URL or unfetched)")
            continue
        if quote.encode() not in sources[hit][1]:
            bad.append(f"[{n}] quote not verbatim in {want}: {quote[:60]!r}")
    for b in bad:
        print(f"citations: {b}", file=sys.stderr)
    if bad:
        return 1
    n_q = len(list(QUOTE_RE.finditer(text)))
    print(f"citations: {n_q} quote(s) verified against saved sources")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
