# PHP2Shell — detection and incident-response signals

Patching is the fix. These signals help you find attempts and possible
compromise around CVE-2026-109618 / CVE-2026-109619.

## On the host

- **Unexpected child processes of PHP workers.** PHP-FPM or Apache `php`
  workers spawning `sh`, `bash`, `python`, `perl`, `curl`, `wget`, or network
  tools is a strong RCE signal. Watch with auditd / EDR process-ancestry rules.
- **PHP worker crashes / segfaults.** Repeated worker restarts, `SIGSEGV` in
  `dmesg`, or FPM "child exited on signal 11" lines can indicate exploitation
  attempts (both CVEs are memory-safety bugs).
- **After patching: the hard memory limit.** Fixed builds add a second memory
  ceiling (`memory_hard_limit_percent`, by default twice `memory_limit`). A
  process that reaches it writes `Hard memory limit of … bytes exhausted` to
  stderr and exits with status 137. On a patched server, that line or a
  worker exiting 137 means a request pushed PHP far past its limit: worth a
  look while attacks against unpatched servers continue.
- **New or modified files in web roots**, especially `.php` files with
  obfuscated content, written around the time of suspicious requests.

## In web/access logs

- POST requests whose body contains `PHP_SESSION_UPLOAD_PROGRESS`.
- Multipart requests with no usable `Content-Length`, with an unusual number
  of headers inside a part, or with many empty file fields and deeply nested
  field names: these are the routes PHP lists for driving a request out of
  memory (CVE-2026-109618).
- Bursts of requests that correlate with worker restarts.

## In PHP's own logs (PHP's audit advice for CVE-2026-109619)

Enable `log_errors=On`, a working `error_log` and `error_reporting=E_ALL` in
startup configuration during an isolated audit, then look for:

- warnings, deprecations and core errors repeated before target scripts run
  (often from `.htaccess`, `php_value` or `PHP_VALUE` settings);
- warnings and other diagnostics produced during extension or server cleanup;
- fatal, parse and uncaught errors, and `Maximum execution time exceeded`;
- failures limited to upload, import, error-page or other attacker-reachable
  routes.

Fixing these removes links in the chain. A clean log is not proof of safety:
the failure can happen before PHP writes anything.

## Suricata (illustrative — tune before production)

```
alert http any any -> $HOME_NET any ( \
    msg:"PHP2Shell session upload-progress field (CVE-2026-109619 session case)"; \
    flow:to_server,established; \
    http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase; \
    classtype:web-application-attack; sid:2026109618; rev:1; )
```

## If you find evidence of compromise

1. Isolate the host from the network.
2. Assume the PHP worker user is compromised; rotate any secrets it could read
   (DB credentials, API keys, `.env`).
3. Preserve logs and a disk image before remediation.
4. Rebuild from known-good rather than cleaning in place.
5. Patch PHP before returning the host to service.
