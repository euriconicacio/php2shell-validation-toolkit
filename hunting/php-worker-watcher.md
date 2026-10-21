# Watching PHP workers for post-exploitation (PHP2Shell)

Successful PHP2Shell exploitation runs code as the PHP worker user. The
highest-signal, lowest-noise detection is a PHP worker (php-fpm / apache
`php`) spawning a child it never legitimately spawns.

## Suspicious child processes of PHP workers

Alert when the parent is `php-fpm`, `php`, `httpd`, or `apache2` and the child
is any of:

- Shells: `sh`, `bash`, `dash`, `zsh`, `ksh`
- Interpreters: `python`, `python3`, `perl`, `ruby`, `node`
- Transfer tools: `curl`, `wget`, `fetch`, `tftp`, `ncat`, `nc`, `socat`
- Recon: `whoami`, `id`, `uname`, `hostname`, `ifconfig`, `ip`, `ps`, `netstat`

Reverse-shell patterns to watch in command lines: `bash -i`, `sh -i`,
`/dev/tcp/`, `mkfifo`, `python -c 'import socket'`, `socat ... EXEC`.

## Linux without an EDR agent

Florian Roth's auditd/process watcher can run in observe mode and flag the
above parent/child relationships. auditd execve rules keyed on the PHP worker
user achieve the same with native tooling.

Example auditd rule (tune the uid to your php-fpm user):

```
-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -F uid=www-data -k php_worker_exec
```

Then review with `ausearch -k php_worker_exec` and alert on shells/interpreters.

## Memory and stability signals

- PHP worker segfaults (`SIGSEGV`, "child exited on signal 11" in FPM logs).
- Unusual RSS growth or OOM kills on PHP hosts (the trigger involves OOM).
- Repeated worker restarts correlated with multipart POST bursts.

## Correlate with the web tier

Join these host signals with access-log hits for `multipart/form-data` POSTs
and the `PHP_SESSION_UPLOAD_PROGRESS` field (see `log-and-ids-detection.md`).
A worker spawning a shell right after such a request is a strong compromise
indicator.
