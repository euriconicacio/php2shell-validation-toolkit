#!/bin/bash
# Differential reachability reproduction for CVE-2026-109618 on PHP 5.3.15.
#
# Brings up three mod_php builds, posts ONE large, well-formed multipart text
# field (an ordinary big form value, not a crafted payload) under a low
# memory_limit, and reports whether the body parser hits OOM before any
# application code runs. Tears the containers down at the end.
#
# This does NOT exploit the bug: it proves the OOM in the parse path is reachable
# from an unauthenticated request. The fixed build (8.3.36) OOMs the same way at
# the HTTP surface — see ../README.md for what that does and does not prove.
#
# Prereqs: docker; the php53lab:5.3.15 image built from ./Dockerfile; internet
# for the two official control images.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
names=(lab53 lab830 lab836)
ports=(8101 8102 8103)
images=(php53lab:5.3.15 php:8.3.0-apache php:8.3.36-apache)
labels=("5.3.15" "8.3.0-prefix" "8.3.36-fixed")
ini_dst=(/usr/local/lib/php.ini /usr/local/etc/php/conf.d/zz-low.ini /usr/local/etc/php/conf.d/zz-low.ini)

cleanup() { for n in "${names[@]}"; do docker rm -f "$n" >/dev/null 2>&1; done; }
trap cleanup EXIT

# a ~7MB field: under the default 8M post_max_size, well above the 2M memory_limit
FIELD="$HERE/field7m.txt"
[ -f "$FIELD" ] || python3 -c "open('$FIELD','wb').write(b'A'*(7*1024*1024))"

echo "== bringing up the three builds =="
for i in 0 1 2; do
  docker rm -f "${names[$i]}" >/dev/null 2>&1
  docker run -d --name "${names[$i]}" -p "127.0.0.1:${ports[$i]}:80" "${images[$i]}" >/dev/null
  docker cp "$HERE/low.ini"  "${names[$i]}:${ini_dst[$i]}"
  docker cp "$HERE/sink.php" "${names[$i]}:/var/www/html/sink.php"
  docker restart "${names[$i]}" >/dev/null
done
for i in 0 1 2; do
  for _ in $(seq 1 20); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${ports[$i]}/sink.php" 2>/dev/null)" = 200 ] && break
    sleep 1
  done
done

echo "== effective config (memory_limit|post_max_size|display_errors) =="
for i in 0 1 2; do
  docker exec "${names[$i]}" sh -c 'printf "<?php echo ini_get(\"memory_limit\"),\"|\",ini_get(\"post_max_size\"),\"|\",ini_get(\"display_errors\"),\"\\n\";" > /var/www/html/v.php'
  printf '  %-14s ' "${labels[$i]}"; curl -s "http://127.0.0.1:${ports[$i]}/v.php"
done

echo
echo "== differential: 7MB multipart text field, memory_limit=2M =="
for i in 0 1 2; do
  n="${names[$i]}"; p="${ports[$i]}"
  code=$(curl -s -o "/tmp/r.$n" -w '%{http_code}' --max-time 60 -F "a=<$FIELD" "http://127.0.0.1:$p/sink.php" 2>/dev/null)
  echo "[${labels[$i]}]"
  echo "  HTTP=$code  body=$(head -c 140 "/tmp/r.$n" | tr '\n' ' ')"
  echo "  php_err: $(docker exec "$n" sh -c 'tail -1 /tmp/php_error.log 2>/dev/null')"
done
echo
echo "Expected: 5.3.15 -> HTTP 500, 'Allowed memory size ... exhausted ... in Unknown on line 0',"
echo "sink.php never runs (empty body). The OOM is in the parser, before application code."
