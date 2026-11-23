---
name: cloud
description: "Focused hunt for cloud-centric vulnerabilities behind web targets: S3/GCS/Azure storage misconfigurations and takeover, cloud resource subdomain takeover (dangling CNAMEs), exposed cloud services and metadata, leaked IAM credentials reuse, and signed-URL abuse. Use when the focus is cloud aspects of a web target or a recon profile shows cloud infrastructure. Not for pure SSRF (use ssrf) or general secrets hunting (use info-leak)."
---

# Cloud Vulnerabilities

## When to use

- "Check the cloud posture of X", "S3/bucket issues on X", "subdomain takeover on X"
- Recon profile shows: S3/GCS/Azure hostnames, CloudFront/ELB/App Runner, CNAMEs to cloud services, static sites on buckets

## When NOT to use

- Pure SSRF to metadata (use `ssrf` — this skill consumes its results)
- Generic secret exposure (use `info-leak`; here only the cloud-credential reuse part)

## Inputs

- **Target** + recon artifacts (`recon/<target>/profile.md` — hostnames, CNAMEs, cloud fingerprints)
- **Tools**: dig/curl for DNS and bucket checks; aws/gcloud/az CLIs only if the user's environment has them and credentials are separate from the target's

## Rationalizations to reject

- "The bucket is public" — public read of public assets is intended. Find private data, listing, or write access before calling it a finding.
- "The CNAME points to a cloud service" — takeover requires the resource to be *unclaimed/deleted*. Register-proof (or a definitive provider error like `NoSuchBucket` with claimable name) is the evidence, not the CNAME alone.
- "The key works" — if you found IAM credentials, prove *minimal* impact (one `GetCallerIdentity`-equivalent) and stop. Don't enumerate the account tree without asking.

## Methodology

### 1. Cloud asset inventory
- DNS: `dig CNAME` on all in-scope hosts. Cloud signatures: `*.cloudfront.net`, `*.elb.amazonaws.com`, `*.s3.amazonaws.com`, `*.s3-website.*`, `*.cloudapp.net`, `*.azurewebsites.net`, `*.trafficmanager.net`, `*.blob.core.windows.net`, `*.storage.googleapis.com`, `*.appspot.com`, `*.herokuapp.com`, `*.pantheon.io`, `*.zendesk.com`, `*.myshopify.com`.
- Static assets/JS: hardcoded bucket URLs, `s3://`, `gs://`, region hints, cloud SDK usage.
- HTTP fingerprints: S3 XML errors, GCP `x-goog-` headers, Azure headers, Lambda function URLs, API Gateway stages (`/dev`, `/prod` in API paths).

### 2. Storage buckets (S3 / GCS / Azure Blob)
- **Enumeration**: guessable names — `company-backups`, `company-dev`, `company-assets`, `company-logs`, `company-staging`, region variants (`company-eu-west-1`), from recon JS findings. Test with direct GET: `https://<bucket>.s3.amazonaws.com/` and path-style `https://s3.amazonaws.com/<bucket>/`.
- **Listing**: GET on the bucket root. S3 ListBucket XML, GCS `?list-type=2`, Blob `?restype=container&comp=list`.
- **Takeover**: bucket referenced by the site but returning `NoSuchBucket` (S3), `NoSuchBucket`/404 on GCS, or missing Azure container. If the provider allows registering that name — that's the takeover. For S3, verify with `aws s3 ls` style calls *only if a separate AWS account is available and the user allows the registration*; otherwise report the dangling reference with the exact error as evidence.
- **Write**: `PUT` a marker object (`.takeover-check` style) only on buckets that already look abandoned or clearly yours; never on active ones without permission.
- **Read**: private-looking files referenced by the app (guess common paths: `backup.sql`, `db.sqlite`, `dump.tar.gz`, `logs/`, `uploads/`).

### 3. Subdomain takeover (cloud resources)
For each dangling CNAME to a claimable service:
- Verify the error signature per provider (CloudFront "Bad request" with `X-Amz-Cf-Id`, S3 NoSuchBucket, Azure `404 ResourceNotFound` on trafficmanager, GCP 404s on appspot).
- Claim-proof: registering the resource name in your own account/subscription and seeing the subdomain serve your content. Only with explicit user approval; otherwise report as verified dangling with error evidence.
- Non-claimable dangling (ELB, blob with SAS) → report as lead/info only.

### 4. Metadata and identity (consumes `ssrf` results)
- If `ssrf` reached metadata: AWS `169.254.169.254` (IMDSv1 vs v2), GCP `metadata.google.internal` (needs `Metadata-Flavor: Google`), Azure `169.254.169.254` (with `Api-Version` header).
- Report exposed metadata endpoints + role names. Never use stolen credentials beyond a single identity check (`GetCallerIdentity`, `whoami`) unless the user asked. Never store found keys in plaintext reports — mask.

### 5. Exposed cloud services
- API Gateway stages without auth (`x-amzn-errortype` in responses), Lambda URLs public, App Runner, ECS/ALB paths, GCP Cloud Run (`*.run.app`), Firebase (`.firebaseio.com`, open RTDB rules `{"rules": {".read": true}}` via `/.json` REST probe), Firestore REST probes.
- Admin panels on cloud managed services: RDS proxy, ElastiCache, DocumentDB (usually not HTTP-reachable — check only what the surface exposes).
- Cloud storage UIs: exposed MinIO (`:9000` or `/minio`), Ceph S3 gateways.

### 6. CORS misconfiguration on cloud frontends
- `Origin: <your-controlled-domain>` and `Origin: <allowed-domain>.your-domain.com` style probes on authed endpoints. If `Access-Control-Allow-Credentials: true` with reflected arbitrary origin → credentialed cross-origin data theft (cross-report to `info-leak` impact narrative).

### 7. Signed URL abuse
- Extract pre-signed URLs from the app (upload/download features). Test: expired? Still valid after logout? Scoped to the right object or the whole bucket (S3 signed URL scope, GCS V4)? Can you alter the object path in the signature-covered region?

## Reporting

`findings/cloud-<date>.md`, family format. Severity: takeover proven = high; private data readable in bucket = high; bucket listing of sensitive content = medium/high; dangling reference not claimed = medium (takeover risk); metadata reachable = high per `ssrf` rules.

## Focus discipline

The SSRF mechanics that got you to metadata belong to `ssrf`; generic JS secrets to `info-leak`; the infrastructure behind (VMs, networks) is out of scope unless the user asks.
