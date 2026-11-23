#!/usr/bin/env bash
# recon deterministic discovery pass: subdomains, liveness, archived/current
# URLs, JS artifacts. Executes methodology steps 1-4 of SKILL.md with tool
# fallbacks built in. Analysis (steps 5-6) stays with the model.
#
# Usage: discover.sh <domain> [outdir] [--brute]
#   --brute: also brute-force common paths on the apex host (needs ffuf + wordlist)
#
# Artifacts written under outdir (default recon/<domain>/):
#   subdomains.txt  live.txt  urls.txt  js/*.js  js-findings.txt  tools-used.txt
set -euo pipefail

usage() { echo "usage: $0 <domain> [outdir] [--brute]" >&2; exit 1; }

[ $# -ge 1 ] || usage
domain="$1"
outdir=""
brute=0
for arg in "$@"; do
  case "$arg" in
    --brute) brute=1 ;;
    *) [ -z "$outdir" ] && [ "$arg" != "$domain" ] && outdir="$arg" ;;
  esac
done
outdir="${outdir:-recon/$domain}"

# Validate domain: letters, digits, hyphens, dots only. No scheme, path, or shell metachars.
if ! printf '%s' "$domain" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'; then
  echo "invalid domain: $domain" >&2
  exit 1
fi

mkdir -p "$outdir/js"
tools="$outdir/tools-used.txt"
: > "$tools"

log() { echo "[*] $*"; }
used() { echo "$1" >> "$tools"; }

log "target: $domain (artifacts: $outdir)"

# --- 1. Subdomain discovery -------------------------------------------------
if command -v subfinder >/dev/null 2>&1; then
  used "subfinder"
  subfinder -d "$domain" -silent > "$outdir/subdomains.txt" || true
else
  used "crt.sh (curl)"
  crt_json=$(curl -sm 30 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null || true)
  if command -v jq >/dev/null 2>&1 && [ -n "$crt_json" ]; then
    used "jq"
    printf '%s' "$crt_json" | jq -r '.[].name_value' 2>/dev/null || true
  elif command -v python3 >/dev/null 2>&1 && [ -n "$crt_json" ]; then
    used "python3 (json fallback)"
    printf '%s' "$crt_json" | python3 -c 'import json,sys;[print(n) for e in json.load(sys.stdin) for n in str(e.get("name_value","")).split("\\n")]' 2>/dev/null || true
  fi | tr '[:upper:]' '[:lower:]' | grep -E "\.${domain}$" | sort -u > "$outdir/subdomains.txt" || : > "$outdir/subdomains.txt"
fi
grep -qE '.' "$outdir/subdomains.txt" 2>/dev/null || : > "$outdir/subdomains.txt"
echo "$domain" >> "$outdir/subdomains.txt"
sort -u "$outdir/subdomains.txt" -o "$outdir/subdomains.txt"
log "subdomains: $(wc -l < "$outdir/subdomains.txt" | tr -d ' ')"

# --- 2. Liveness --------------------------------------------------------------
: > "$outdir/live.txt"
if command -v httpx >/dev/null 2>&1; then
  used "httpx"
  httpx -silent -title -tech-detect -timeout 10 < "$outdir/subdomains.txt" > "$outdir/live.txt" 2>/dev/null || true
else
  used "curl (liveness fallback)"
  while IFS= read -r host; do
    [ -n "$host" ] || continue
    for scheme in https http; do
      res=$(curl -sm 10 -o /dev/null -w '%{http_code} %{url_effective}' -L "${scheme}://${host}" 2>/dev/null || true)
      if [ -n "$res" ] && [ "${res%% *}" != "000" ]; then
        echo "$host $res" >> "$outdir/live.txt"
        break
      fi
    done
  done < "$outdir/subdomains.txt"
fi
log "live hosts: $(wc -l < "$outdir/live.txt" | tr -d ' ')"

# --- 3. URL / endpoint discovery ----------------------------------------------
: > "$outdir/urls.txt"
if command -v katana >/dev/null 2>&1 && [ -s "$outdir/live.txt" ]; then
  used "katana"
  cut -d' ' -f1 "$outdir/live.txt" | katana -list /dev/stdin -d 3 -silent 2>/dev/null >> "$outdir/urls.txt" || true
fi
used "wayback cdx (curl)"
curl -sm 40 "http://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey" 2>/dev/null \
  | grep -E "^https?://" >> "$outdir/urls.txt" || true
sort -u "$outdir/urls.txt" -o "$outdir/urls.txt"
log "urls: $(wc -l < "$outdir/urls.txt" | tr -d ' ')"

# --- 4. JS collection ---------------------------------------------------------
js_seen="$outdir/js/.seen"
: > "$js_seen"
collect_js() {
  # $1 = page URL
  html=$(curl -sm 15 -L "$1" 2>/dev/null || true)
  [ -n "$html" ] || return 0
  printf '%s' "$html" | grep -oE '(src|href)="[^"]+\.js[^"]*"' | sed -E 's/^[a-z]+="//; s/"$//' | while IFS= read -r jsurl; do
    case "$jsurl" in
      http*) : ;;
      //*) jsurl="https:$jsurl" ;;
      /*) jsurl="$(printf '%s' "$1" | grep -oE '^https?://[^/]+')$jsurl" ;;
      *) jsurl="$(dirname "$1")/$jsurl" ;;
    esac
    echo "$jsurl" >> "$js_seen"
  done
}
# JS from live host landing pages
if [ -s "$outdir/live.txt" ]; then
  while IFS= read -r line; do
    host=$(printf '%s' "$line" | awk '{print $1}')
    collect_js "https://${host}" || true
  done < "$outdir/live.txt"
fi
# JS URLs already present in the URL list
grep -E '\.js($|\?)' "$outdir/urls.txt" >> "$js_seen" 2>/dev/null || true
sort -u "$js_seen" -o "$js_seen"

n=0
while IFS= read -r jsurl; do
  [ -n "$jsurl" ] || continue
  n=$((n+1))
  fname=$(printf '%s' "$jsurl" | sed -E 's#https?://##; s#[/?&=]#_#g' | cut -c1-120)
  curl -sm 20 -L "$jsurl" -o "$outdir/js/${n}-${fname}" 2>/dev/null || rm -f "$outdir/js/${n}-${fname}"
done < "$js_seen"
rm -f "$js_seen"
log "js files: $(find "$outdir/js" -type f -name '*.js*' | wc -l | tr -d ' ')"

# --- 5. JS findings (routes, keys, internal hosts) ----------------------------
{
  echo "== API routes =="
  grep -rhoE '"/(api|v[0-9]+)/[^"]+"' "$outdir/js" 2>/dev/null | sort -u || true
  echo "== hardcoded key patterns =="
  grep -rhniE 'api[_-]?key|secret|token|password|bearer' "$outdir/js" 2>/dev/null \
    | grep -viE 'apikey.{0,3}[:=].{0,3}["'"'"']?(process\.env|import\.meta)' | head -50 || true
  echo "== internal hostnames =="
  grep -rhoE "https?://[a-zA-Z0-9.-]*\.${domain//./\\.}" "$outdir/js" 2>/dev/null | sort -u | head -30 || true
} > "$outdir/js-findings.txt"
log "js findings: $outdir/js-findings.txt"

# --- 6. Optional: common-path brute force on apex -----------------------------
if [ "$brute" = 1 ]; then
  if command -v ffuf >/dev/null 2>&1; then
    wl=""
    for w in /usr/share/wordlists/raft-small-words.txt \
             /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
             /usr/share/wordlists/common.txt; do
      [ -f "$w" ] && wl="$w" && break
    done
    if [ -n "$wl" ]; then
      used "ffuf ($wl)"
      ffuf -w "$wl" -u "https://${domain}/FUZZ" -t 20 -timeout 10 \
        -mc 200,201,204,301,302,307,401,403,405,500 -o "$outdir/common-paths.json" \
        -of json -silent 2>/dev/null || true
      log "brute force: $outdir/common-paths.json"
    else
      log "brute skipped: no wordlist found (install SecLists or add one to the search list)"
    fi
  else
    log "brute skipped: ffuf not installed"
  fi
fi

log "done. Next (manual per SKILL.md): tech fingerprinting, param mining, write profile.md"
