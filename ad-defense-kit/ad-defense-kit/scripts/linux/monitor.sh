#!/usr/bin/env bash
# monitor.sh — leave running in a spare terminal. Read-only.
# Prints new successful logins + new listeners + suspicious procs as they appear.
set -u
AUTH=/var/log/auth.log; [ -f /var/log/secure ] && AUTH=/var/log/secure
echo "[*] watching $AUTH  (Ctrl-C to stop)"

# baseline listeners
prev_listen=$(ss -tulpn 2>/dev/null | sort)

tail -Fn0 "$AUTH" 2>/dev/null | grep --line-buffered -Ei 'Accepted|sudo:.*COMMAND|new user|useradd|password changed' &
TAILPID=$!

trap 'kill $TAILPID 2>/dev/null; exit' INT TERM

while true; do
  cur_listen=$(ss -tulpn 2>/dev/null | sort)
  diff <(echo "$prev_listen") <(echo "$cur_listen") | grep '^>' | sed 's/^> /[NEW LISTENER] /'
  prev_listen=$cur_listen
  ps aux | grep -Ei 'nc -e|bash -i|/dev/tcp|socat.*exec|python.*socket|perl.*socket' | grep -v grep \
    | sed 's/^/[SUSPECT PROC] /'
  sleep 3
done
