# Cloudflare WAF mitigation — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

Edge rules to blunt PHP2Shell while you patch. **Stopgap, not a fix.** Cloudflare
deployed managed protections by default on 2026-10-21; these custom rules add
defense in depth and cover origins you also expose directly.

## Rule 1 — Block multipart uploads on write methods (all plans)

Use a Custom Rule (WAF → Custom rules). Expression:

```
(http.request.method in {"POST" "PUT" "PATCH"}
 and http.request.headers["content-type"][0] contains "multipart/form-data")
```

Action: **Block**.

This breaks legitimate uploads. Scope it so upload routes are excluded:

```
(http.request.method in {"POST" "PUT" "PATCH"}
 and http.request.headers["content-type"][0] contains "multipart/form-data"
 and not starts_with(http.request.uri.path, "/wp-admin/")
 and not starts_with(http.request.uri.path, "/upload"))
```

Adjust the excluded paths to the upload endpoints your app actually needs.

## Rule 2 — Inspect the body for the trigger field (Enterprise / body inspection)

Where request-body inspection is available:

```
(http.request.body.raw contains "PHP_SESSION_UPLOAD_PROGRESS")
```

Action: **Block**. This is more precise than blocking all multipart traffic.

## What NOT to do

- Do **not** key the rule on the `PHPSESSID` cookie alone. The trigger does not
  require an existing session, so cookie-based rules miss the attack and may
  block legitimate users.

## After patching

Remove or disable these rules once every origin PHP is on a fixed release, so
you stop breaking multipart uploads.
