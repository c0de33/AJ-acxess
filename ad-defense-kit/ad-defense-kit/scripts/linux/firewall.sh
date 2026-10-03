#!/usr/bin/env bash
# firewall.sh — default-deny inbound, allow only what you list below.
#
#   !!! EDIT THE TWO LISTS BELOW BEFORE RUNNING !!!
#   !!! HAVE A SECOND SSH SESSION OPEN BEFORE YOU RUN THIS !!!
#
# Wrong ports here = you lock yourself out OR you drop a scored service.
set -euo pipefail

# ---- EDIT ME ----------------------------------------------------------
MGMT_PORT=22                       # the port YOU use to get in (SSH). Never omit.
SCORED_PORTS=(80 443)              # ports scored for availability — ADD YOURS
ALLOW_ICMP=true                    # ping often used by scoring engine; keep true
# ----------------------------------------------------------------------

echo "[*] Management port : $MGMT_PORT"
echo "[*] Scored ports    : ${SCORED_PORTS[*]}"
read -rp "These correct? Ctrl-C to abort, Enter to apply: " _

apply_ufw(){
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "$MGMT_PORT"/tcp
  for p in "${SCORED_PORTS[@]}"; do ufw allow "$p"/tcp; done
  $ALLOW_ICMP && sed -i 's/^-A ufw-before-input -p icmp .*echo-request.*DROP/# &/' /etc/ufw/before.rules 2>/dev/null || true
  ufw --force enable
  ufw status verbose
}

apply_nft(){
  nft flush ruleset
  nft add table inet filter
  nft add chain inet filter input '{ type filter hook input priority 0 ; policy drop ; }'
  nft add chain inet filter forward '{ type filter hook forward priority 0 ; policy drop ; }'
  nft add chain inet filter output '{ type filter hook output priority 0 ; policy accept ; }'
  nft add rule inet filter input ct state established,related accept
  nft add rule inet filter input iif lo accept
  $ALLOW_ICMP && nft add rule inet filter input ip protocol icmp accept
  nft add rule inet filter input tcp dport "$MGMT_PORT" accept
  for p in "${SCORED_PORTS[@]}"; do nft add rule inet filter input tcp dport "$p" accept; done
  nft list ruleset
}

if command -v ufw >/dev/null 2>&1; then
  echo "[*] Using ufw"; apply_ufw
elif command -v nft >/dev/null 2>&1; then
  echo "[*] Using nftables"; apply_nft
else
  echo "[!] Neither ufw nor nft found. Install one, or use iptables manually."; exit 1
fi

echo
echo "[✓] Firewall applied. NOW: from another host, test every scored port responds."
echo "    If a scored service is down, add its port above and re-run."
