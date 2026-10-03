# RUNBOOK — what to run, in what order, and why

Follow top to bottom on game day. Windows scripts run in **admin PowerShell**; before the first
`.ps1` in a window: `Set-ExecutionPolicy -Scope Process Bypass` (and `Unblock-File .\name.ps1` if
a script is blocked from being a downloaded file). Linux scripts run as **root** (`sudo bash name.sh`).

THE RULE THAT DECIDES IT: availability is scored. Baseline first → change ONE thing → retest the
service still responds → next. Slow is fast.

---

## PHASE 0 — Baseline (first, before touching anything)  [READ-ONLY, safe]

| Order | Run | Where | Purpose |
|---|---|---|---|
| 0.1 | `.\recon.ps1 \| Tee-Object baseline_win.txt` | each Windows box | Snapshot users, ports, services, tasks. Saves a "known good" you can diff against later. |
| 0.2 | `.\ad_recon.ps1 \| Tee-Object ad_baseline.txt` | the DC | Tells you DC vs member, dumps privileged groups, kerberoastable accts, DCSync rights, krbtgt date. |
| 0.3 | `sudo bash recon.sh \| tee baseline_lin.txt` | each Linux box | Same snapshot for Linux: users, listeners, cron, SUID, keys. |
| 0.4 | (manual) | — | Fill the **Scored Services** tab in the xlsx. You can't protect availability you didn't write down. |

## PHASE 1 — Persistence hunt (before firewalling — if they're already in, a firewall won't help)  [READ-ONLY]

| Order | Run | Where | Purpose |
|---|---|---|---|
| 1.1 | `.\persistence.ps1 \| Tee-Object persist_win.txt` | each Windows box | Finds attacker cron/tasks/run-keys/services/WMI backdoors + rogue admins. |
| 1.2 | `sudo bash persistence.sh \| tee persist_lin.txt` | each Linux box | Same hunt for Linux: cron, systemd, rc files, LD_PRELOAD, SUID, reverse shells. |
| 1.3 | (manual) | — | Verify each hit, remove it, log it in the **Incident Log** tab. Don't nuke blindly. |

## PHASE 2 — Credentials & AD lockdown (kill the easy foothold)

| Order | Run | Where | Purpose |
|---|---|---|---|
| 2.1 | `.\ad_baseline_gpo.ps1` | the DC | Pushes hardening to EVERY joined box at once: pw policy, Protected Users, RunAsPPL (blocks mimikatz), SMBv1/LLMNR/WDigest off, SMB signing, audit. |
| 2.2 | `.\ad_harden.ps1` | the DC | Purge unexpected admins → reset Domain Admin pws → **krbtgt double-reset** (kills Golden Tickets) → reset SPN accts → check DCSync/AdminSDHolder/SIDHistory backdoors. Prompts before each. |
| 2.3 | `.\harden.ps1` | each Windows member | Local creds, disable Guest, SMBv1 off, logging. Log every new pw in **Creds Tracker**. |
| 2.4 | `sudo bash harden.sh` | each Linux box | Rotate creds, backdoor-account check, SSH hardening (keep a 2nd session open), config backup. |

## PHASE 3 — Firewall (lock the network WITHOUT breaking your own domain)

| Order | Run | Where | Purpose |
|---|---|---|---|
| 3.1 | **read** `AD_PORTS_AND_TIERING.md` | — | The DC needs AD ports open to your members or you break domain auth/GPO/replication yourself. |
| 3.2 | **DO NOT run firewall.ps1 on the DC.** Configure the DC by hand per the port table, internal subnet only. | the DC | Default-deny on the DC = self-inflicted outage. |
| 3.3 | `.\firewall.ps1` (EDIT `$MyIP` + scored ports at top FIRST) | Windows member/mail box | Default-deny inbound, allow RDP-from-you + scored ports. |
| 3.4 | `bash firewall.sh` (EDIT the PORTS list at top FIRST) | each Linux box | Same: default-deny, allow mgmt + scored. Keep a 2nd SSH session open. |
| 3.5 | (manual) | — | After EVERY rule change, test each scored service from another host. Down? Revert the last rule. |

## PHASE 4 — Monitor (leave running the whole round)  [READ-ONLY]

| Order | Run | Where | Purpose |
|---|---|---|---|
| 4.1 | `.\monitor.ps1` | each Windows box (spare window) | Live: new logons, brute-force, new listeners, suspect processes. |
| 4.2 | `sudo bash monitor.sh` | each Linux box (spare terminal) | Live: successful logins, new listeners, reverse-shell-looking procs. |
| 4.3 | re-run **Phase 1** persistence scripts every ~30 min | all boxes | They WILL try to walk back in after you kick them. Re-hunt = they can't re-score on you. |

## CTF side (separate person if you have the team for it)
- `CTF_REV_PWN.md` — install the toolbox this week (Ghidra, pwntools, gdb+pwndbg, checksec).
- When you hit a challenge, bring me the `file`/`checksec`/`strings` output + decompiled `main`.

---

### Tiny cheat-summary
```
DC:            ad_recon → ad_baseline_gpo → ad_harden        (never firewall.ps1)
Windows member: recon → persistence → harden → firewall → monitor
Linux box:     recon.sh → persistence.sh → harden.sh → firewall.sh → monitor.sh
Every PS window first: Set-ExecutionPolicy -Scope Process Bypass
```
