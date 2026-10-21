# PHP2Shell test lab (isolated)

This lab exists so you can **validate the toolkit itself** against a known-bad
PHP: confirm that the exposure checker reports `VULNERABLE`, that your WAF /
ModSecurity rules block the trigger, and that your log and IDS signals fire.

It is **not** an exploit and it does not teach exploitation. It is a target for
your *defensive* checks.

## Rules of use

- Run it only on a host you control.
- The compose file binds the web port to `127.0.0.1` and puts the container on
  an `internal` network with no outbound access. Keep it that way.
- Tear it down when you are done: `docker compose down`.

## Suggested flow

1. `docker compose up -d`
2. Point the exposure checker at it:
   `python3 ../exposure/check_php2shell.py --url http://localhost:8088`
   Expect `VULNERABLE` (the image is an old, pre-fix PHP).
3. Put a proxy with your `mitigations/` rules in front of it and confirm the
   trigger (`PHP_SESSION_UPLOAD_PROGRESS`) is blocked.
4. Tail the container logs and confirm your `hunting/` signals match.
5. Swap the image tag to a patched release and confirm the checker flips to
   `PATCHED`.
