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
- **New or modified files in web roots**, especially `.php` files with
  obfuscated content, written around the time of suspicious requests.

## In web/access logs

- POST requests whose body contains `PHP_SESSION_UPLOAD_PROGRESS`.
- `multipart/form-data` uploads with abnormally long inter-chunk delays
  (the UAF race depends on a timed stall mid-upload).
- Bursts of requests that correlate with worker restarts.

## Suricata (illustrative — tune before production)

```
alert http any any -> $HOME_NET any ( \
    msg:"PHP2Shell session upload-progress trigger (CVE-2026-109618)"; \
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
