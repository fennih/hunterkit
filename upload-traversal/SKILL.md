---
name: upload-traversal
description: "Focused hunt for file upload bypasses, path traversal, and local/remote file inclusion on a web target. Use when the focus is upload features, arbitrary file read, LFI/RFI, or filename handling. Not for command injection into converters (use cmd-injection) or SSRF via from-URL uploads (use ssrf)."
---

# File Upload, Path Traversal, LFI/RFI

## When to use

- "Test upload feature of X", "hunt LFI on X", "arbitrary file read on X"
- OWASP coverage: A01/A04-related path traversal, unrestricted upload (CWE-434, CWE-22, CWE-98)

## When NOT to use

- Command injection in file processing (use `cmd-injection`)
- Upload-from-URL fetching (use `ssrf`)

## Inputs

- **Target**: upload endpoints, download/export endpoints, avatar/profile features (from `recon` profile if available)
- **Accounts**: one test account for uploads

## Ground rules

- Upload only test files; never overwrite existing user files on purpose except your own.
- Webshell upload: only prove upload + one controlled read (e.g. `whoami` or a marker file); clean up after.
- Every finding needs the exact upload request and proof of where/how the file is served or the traversal output.

## Methodology

### 1. Upload enumeration
Find every upload: avatars, attachments, imports, exports, CSV/logo/theme upload, resume, chat files. Note accepted types (client-side vs server-side checks) by uploading a canary `.txt` renamed `.png` etc.

### 2. Content-type and extension bypass
- Extension tricks: `.php5`, `.phtml`, `.phar`, `.svg` (SVG can carry JS), `.shtml`, double extension `a.png.php`, trailing dot/space `a.php.`, `a.php%00.png` (old stacks), case `.PhP`, `.js`, `.html`.
- Content-Type vs magic bytes: send mismatched `Content-Type: image/png` with script content; polyglots only if simple bypasses fail.
- SVG: upload `<svg><script>alert(1)</script></svg>` or XXE-carrying SVG (also note XXE lead).
- Where does it land? Same origin (dangerous) vs CDN/asset host (safer). Check `Content-Type` and `Content-Disposition` of the served file.

### 3. Path traversal on upload
- Filename `../../test.txt`, `..%2ftest.txt`, absolute `/tmp`-style probes; check if you can control the storage path or overwrite known files (carefully: your own first).

### 4. Path traversal / LFI on read & include patterns
- Params like `?file=`, `?path=`, `?page=`, `?template=`, `?doc=`, `?lang=`, download endpoints, PDF/print views.
- Payloads: `../../../../etc/passwd`, `..%2f..%2f`, `....//`, `%2e%2e/`, UTF-8 overlong `..%c0%af`, semicolon/params appended.
- Windows targets: `..\..\windows\win.ini`.
- Wrappers: `php://filter/convert.base64-encode/resource=index.php` (source read), `file://`, `data://`; RFI via `http://` if allow_url_include suspected (canary only).
- Log/require evidence: actual file content in response.

### 5. Zip/extract and import handling
If the app unzips server-side: zip-slip (`../../` entry names inside the archive) and zip-bomb leads (note bomb, don't detonate beyond a small probe).

### 6. Served-file behavior
- Uploaded HTML/SVG served inline on the main origin → stored XSS (report also under injection coverage, cross-reference).
- Download endpoints that don't force `Content-Disposition: attachment` on HTML files.

## Reporting

Write findings to `findings/upload-traversal-<date>.md`:

```
### [SEVERITY] Title
- Endpoint: method + URL
- CWE: CWE-434 / CWE-22 / CWE-98
- Evidence: upload/download request(s) + served content or file-content response
- Reproduction: numbered steps
- Impact: RCE via webshell, arbitrary file read, stored XSS, file overwrite
```

## Focus discipline

If upload processing leads to command execution via converters, hand off to `cmd-injection`; upload-from-URL to `ssrf`.
