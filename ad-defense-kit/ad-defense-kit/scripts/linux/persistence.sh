#!/usr/bin/env bash
# persistence.sh — READ-ONLY hunt for attacker persistence. Changes nothing.
# Re-run every ~30 min. Anything flagged, verify then remove manually + log it.
set -u
flag(){ printf '\n### %s ###\n' "$1"; }

flag "UID 0 accounts (should be ONLY root)"
awk -F: '$3==0{print $1}' /etc/passwd | grep -v '^root$' && echo "  ^^ BACKDOOR ACCOUNT" || echo "clean"

flag "Empty-password accounts"
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || echo "need root"

flag "Recently modified authorized_keys (last 2 days)"
find / -name authorized_keys -mtime -2 2>/dev/null

flag "All authorized_keys contents"
find / -name authorized_keys 2>/dev/null -exec echo "-- {} --" \; -exec cat {} \;

flag "Cron — per user"
for u in $(cut -f1 -d: /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "## $u ##" && echo "$c"
done
flag "Cron — system + drop dirs"
cat /etc/crontab 2>/dev/null
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  ls -la "$d" 2>/dev/null
done

flag "systemd units modified recently"
find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' -mtime -2 2>/dev/null
flag "systemd timers"
systemctl list-timers --all --no-pager 2>/dev/null

flag "rc.local / init hooks"
cat /etc/rc.local 2>/dev/null
ls -la /etc/init.d 2>/dev/null | tail -n +2

flag "Shell rc files w/ suspicious content"
for f in /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.bash_profile; do
  [ -f "$f" ] && grep -En 'curl|wget|nc |bash -i|/dev/tcp|python -c|base64 -d|eval' "$f" 2>/dev/null | sed "s|^|$f: |"
done
flag "profile.d drops"
grep -rEn 'curl|wget|nc |bash -i|/dev/tcp|base64 -d' /etc/profile.d 2>/dev/null

flag "LD_PRELOAD hijack (should be empty)"
cat /etc/ld.so.preload 2>/dev/null || echo "no ld.so.preload — good"
env | grep -i LD_PRELOAD

flag "SUID/SGID binaries"
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null

flag "Listeners bound to shells / odd binaries"
ss -tulpn 2>/dev/null | grep -Ei 'nc|ncat|bash|python|perl|socat'

flag "Processes running deleted binaries"
ls -la /proc/*/exe 2>/dev/null | grep -i deleted

flag "Reverse-shell-looking processes"
ps aux | grep -Ei 'nc -e|bash -i|/dev/tcp|socat.*exec|python.*socket' | grep -v grep

echo; echo "persistence hunt done — verify hits before removing, then log in Incident Log."
