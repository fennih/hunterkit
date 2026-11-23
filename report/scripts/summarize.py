#!/usr/bin/env python3
"""Summarize findings/*.md into a severity-grouped index.

Usage: python3 summarize.py <findings-dir> [outfile]
Parses '### [SEVERITY] Title' headers; groups by severity; prints and writes markdown.
"""
import sys
import re
import pathlib

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    d = pathlib.Path(sys.argv[1])
    if not d.is_dir():
        print(f"not a directory: {d}", file=sys.stderr)
        sys.exit(1)

    findings = []
    for f in sorted(d.glob("*.md")):
        for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            m = re.match(r"^#{2,4}\s+\[([A-Za-z]+)\]\s+(.+)$", line.strip())
            if m:
                sev = m.group(1).lower()
                if sev in ORDER:
                    findings.append((sev, m.group(2).strip(), f.name, i))

    findings.sort(key=lambda x: (ORDER[x[0]], x[2], x[3]))

    lines = ["# Findings summary", ""]
    counts = {s: 0 for s in ORDER}
    for sev, title, fname, lineno in findings:
        counts[sev] += 1
        lines.append(f"- **[{sev.upper()}]** {title} — `{fname}:{lineno}`")
    lines += ["", "## Counts", ""]
    for sev in ORDER:
        lines.append(f"- {sev}: {counts[sev]}")
    lines += ["", f"Total: {len(findings)}"]

    out = "\n".join(lines) + "\n"
    print(out)
    if len(sys.argv) > 2:
        pathlib.Path(sys.argv[2]).write_text(out)
        print(f"written: {sys.argv[2]}", file=sys.stderr)


if __name__ == "__main__":
    main()
