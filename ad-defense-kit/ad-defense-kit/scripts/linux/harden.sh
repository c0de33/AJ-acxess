#!/usr/bin/env bash
# harden.sh — CAREFUL, semi-interactive hardening. Does NOT touch the firewall
# (use firewall.sh) and does NOT mass-kill services. Read each prompt.
set -uo pipefail
ok(){ printf '\n[+] %s\n' "$1"; }
ask(){ read -rp "$1 [y/N] " a; [[ "$a" == [yY] ]]; }

ok "1. Root password"
if ask "Change root password now?"; then passwd root; fi

ok "2. Change all human-user passwords to unique values"
echo "    (writes them to ./new_creds.txt — MOVE THIS OFF THE BOX AFTER)"
if ask "Rotate all UID>=1000 user passwords?"; then
  : > ./new_creds.txt
  for u in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
    np="C0mp!$(tr -dc A-Za-z0-9 </dev/urandom | head -c8)"
    echo "$u:$np" | chpasswd && echo "$u : $np" >> ./new_creds.txt
  done
  echo "    saved -> ./new_creds.txt"; cat ./new_creds.txt
fi

ok "3. Backdoor account check (UID 0 other than root)"
awk -F: '$3==0 && $1!="root"{print "  SUSPECT: "$1}' /etc/passwd || echo "  none"

ok "4. Lock accounts you don't need (manual)"
echo "    To lock:  usermod -L <user>   (NOT the account you're logged in as)"

ok "5. SSH hardening (edits sshd_config; TEST in a 2nd session before logout)"
if ask "Disable root SSH login + password auth stays ON?"; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
  sshd -t && systemctl reload sshd && echo "    reloaded. TEST a new SSH session NOW."
fi

ok "6. Snapshot good state for fast recovery"
if ask "Back up /etc + key configs to ./config_backup.tgz?"; then
  tar czf ./config_backup.tgz /etc/ssh /etc/passwd /etc/shadow /etc/crontab /etc/systemd 2>/dev/null
  echo "    -> ./config_backup.tgz"
fi

echo; echo "[✓] harden.sh done. Firewall is separate: run firewall.sh."
