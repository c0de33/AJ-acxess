#!/usr/bin/env bash
# recon.sh — READ-ONLY baseline of a Linux box. Changes nothing.
# Run FIRST, save the output:  sudo bash recon.sh | tee baseline_lin_$(hostname).txt
set -u
line(){ printf '\n===== %s =====\n' "$1"; }

line "HOST / KERNEL / TIME"
hostname; uname -a; date; uptime

line "USERS (login-capable)"
awk -F: '$7 !~ /(nologin|false)$/ {print $1"  uid="$3"  shell="$7}' /etc/passwd

line "UID 0 ACCOUNTS  (only 'root' should show)"
awk -F: '$3==0{print $1}' /etc/passwd

line "SUDOERS"
cat /etc/sudoers 2>/dev/null | grep -vE '^\s*#|^\s*$'
for f in /etc/sudoers.d/*; do [ -f "$f" ] && echo "-- $f --" && cat "$f"; done 2>/dev/null

line "LISTENING SERVICES  (map every port to a process)"
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null

line "ESTABLISHED CONNECTIONS"
ss -tnp 2>/dev/null | head -50

line "RUNNING SYSTEMD SERVICES"
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -60

line "SYSTEMD TIMERS"
systemctl list-timers --all --no-pager 2>/dev/null

line "CRON — per user"
for u in $(cut -f1 -d: /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && echo "## $u ##" && echo "$c"
done
line "CRON — system"
cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily 2>/dev/null

line "SSH authorized_keys (anywhere)"
find / -name authorized_keys 2>/dev/null -exec echo "-- {} --" \; -exec cat {} \;

line "SUID / SGID BINARIES  (diff this vs a clean box)"
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null

line "STARTUP / RC FILES"
cat /etc/rc.local 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null; ls -la /etc/profile.d 2>/dev/null

line "STAGING DIRS"
ls -la /tmp /var/tmp /dev/shm 2>/dev/null

line "PROCESSES WITH DELETED BINARIES  (classic malware tell)"
ls -la /proc/*/exe 2>/dev/null | grep -i deleted

echo; echo "recon done."
