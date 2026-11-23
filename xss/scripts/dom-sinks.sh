#!/usr/bin/env bash
# xss DOM sink/source enumeration. Executes the grep part of SKILL.md
# methodology step 3 (DOM) deterministically; tracing and payload crafting stay
# with the model.
#
# Usage: dom-sinks.sh <file-or-dir> [<file-or-dir>...]
#
# Output: per-match file:line, classified SINK / SOURCE / HANDLER, then a
# ranked list of files containing both a sink and a source (candidate flows).
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <file-or-dir>..." >&2; exit 1; }

SINKS='innerHTML|outerHTML|insertAdjacentHTML|document\.write(ln)?|[^a-zA-Z]eval\(|\.html\(|srcdoc|location\.(href|assign|replace)[^a-zA-Z]|window\.open|dangerouslySetInnerHTML|v-html|setTimeout\(|setInterval\(|\$\(.*\)\.html|\.append\(.*<'
SOURCES='location\.(hash|search|href|pathname)|document\.(referrer|URL|documentURI)|URLSearchParams|window\.name|postMessage|onmessage|addEventListener\(.message.'

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

files=()
for target in "$@"; do
  if [ -d "$target" ]; then
    while IFS= read -r f; do files+=("$f"); done < <(find "$target" -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.jsx' -o -name '*.ts' -o -name '*.html' \))
  elif [ -f "$target" ]; then
    files+=("$target")
  else
    echo "not found: $target" >&2
  fi
done

[ ${#files[@]} -gt 0 ] || { echo "no js/html files found" >&2; exit 1; }

echo "== SINKS =="
grep -nE "$SINKS" "${files[@]}" 2>/dev/null | head -200 || true

echo
echo "== SOURCES =="
grep -nE "$SOURCES" "${files[@]}" 2>/dev/null | head -200 || true

echo
echo "== CANDIDATE FLOWS (file has both sink and source — trace these first) =="
for f in "${files[@]}"; do
  if grep -qE "$SINKS" "$f" 2>/dev/null && grep -qE "$SOURCES" "$f" 2>/dev/null; then
    echo "$f"
    echo "$f" >> "$tmp"
  fi
done
[ -s "$tmp" ] || echo "(none — sinks and sources are in different files: check script load order)"
