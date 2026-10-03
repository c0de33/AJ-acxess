# Attack & Defense — Defense Kit

Everything I need to lock down my boxes in a live A&D competition, in one repo I can pull anywhere.

**New here / game day? Open `RUNBOOK.md` — it's the step-by-step: what to run, where, in what order, and why.**

## The one rule
**Availability is scored.** Breaking a scored service while hardening loses points even if nobody hacks you.
That is what cost points last time. So: **baseline first → harden carefully → re-test scored services after every change.**

## Order of operations (first ~30 min decides it)
0. **Recon / baseline** — run the recon scripts, save output, fill `Scored Services` tab.
1. **Credentials** — change every password, kill backdoor/extra accounts, wipe unknown SSH keys.
2. **Persistence hunt** — cron / tasks / services / keys. Do this *before* firewalling; if they're already in, a firewall won't save you.
3. **Firewall** — default-deny inbound, allow scored + your mgmt access. Second session open first.
4. **Service hardening** — patch/config the scored services themselves.
5. **Monitor** — tail logs + connections all round; re-hunt persistence every ~30 min.

## Files
```
AD_Defense_Checklist.xlsx     full checklist (start on "START HERE" tab)
scripts/linux/
  recon.sh          read-only baseline
  persistence.sh    read-only persistence hunt (re-run often)
  firewall.sh       default-deny + allow (EDIT PORTS AT TOP FIRST)
  harden.sh         careful interactive hardening (creds/ssh/backup)
  monitor.sh        live auth + listener + reverse-shell watch
scripts/windows/
  recon.ps1         read-only baseline
  persistence.ps1   read-only persistence hunt (re-run often)
  firewall.ps1      default-deny + allow (EDIT VARS FIRST)
  harden.ps1        careful hardening (creds/guest/smbv1/logging)
  monitor.ps1       live logon + listener + suspect-proc watch
  ad_recon.ps1      read-only Active Directory enum (domain-joined)
  ad_harden.ps1     AD hardening: priv groups, krbtgt double-reset, DCSync/ACL backdoors
```

## Usage
Linux (as root):
```bash
bash scripts/linux/recon.sh | tee baseline_lin.txt
bash scripts/linux/persistence.sh | tee persist_lin.txt
# EDIT the PORTS list in firewall.sh, keep a 2nd SSH session open, then:
bash scripts/linux/firewall.sh
bash scripts/linux/harden.sh
bash scripts/linux/monitor.sh    # leave running
```
Windows (admin PowerShell — may need `Set-ExecutionPolicy -Scope Process Bypass`):
```powershell
.\scripts\windows\recon.ps1 | Tee-Object baseline_win.txt
.\scripts\windows\persistence.ps1 | Tee-Object persist_win.txt
# EDIT the vars in firewall.ps1 (MyIP + scored ports), keep RDP session open, then:
.\scripts\windows\firewall.ps1
.\scripts\windows\harden.ps1
.\scripts\windows\monitor.ps1    # leave running
```

## Domain-joined Windows (AD)
Local password changes **do not** stop a domain admin or a forged Kerberos ticket. If there's AD in your pod, the `Active Directory` tab + `ad_*.ps1` are where the Windows box is won.
```powershell
.\scripts\windows\ad_recon.ps1 | Tee-Object ad_baseline.txt   # tells you DC vs member
.\scripts\windows\ad_harden.ps1                                # DC-owner: full mitigations
```
- **You own the DC:** purge privileged groups → reset all Domain Admin pws → **krbtgt double-reset** (two resets ~10 min apart kills Golden Tickets) → reset SPN service accounts (Silver Tickets) → check AdminSDHolder / DCSync-rights / SIDHistory backdoors → review GPOs.
- **Member only:** can't reset krbtgt. Remove domain users from local Administrators, restrict interactive/RDP logon to your team, watch events 4672/4624 for DA logons, use LAPS if present.

## You own the DC + join members (mail server etc.)
The DC is a single point of total compromise, so two things beat any single exploit — see `scripts/windows/AD_PORTS_AND_TIERING.md`:
1. **Credential tiering.** Domain Admin creds log on ONLY to the DC — never RDP a DA into the mail server, or a popped member hands the attacker your DA hash and the whole domain. Administer members with LAPS/Tier-1 accounts. Put DAs in **Protected Users**, enable **RunAsPPL** (blocks mimikatz).
2. **Don't over-firewall the domain.** A default-deny DC that only allows "scored ports" kills domain auth/GPO/replication for your own members. Allow the AD port set (53/88/123/135/389/445/464/636/3268-9/RPC) DC↔members, scoped to the internal subnet. Only mail/web face the attacker network.

Push the baseline to every joined box at once from the DC:
```powershell
.\scripts\windows\ad_baseline_gpo.ps1   # pw policy, Protected Users, RunAsPPL, SMBv1/LLMNR/WDigest off, SMB signing, audit
```

## Golden don'ts
- No SSH/RDP/firewall change without a **second session already open**.
- Never enable the firewall before allowing your own access **and** scored ports.
- Don't mass-disable services you didn't positively identify — one may be scored.
- Unique password per account; log every change in the `Creds Tracker` tab.
- Assume the boxes are dirty at t=0 — hunt persistence before trusting them.
- Keep `new_creds.txt` / the checklist **off** the competition machines.

## Notes
- Scripts are conservative on purpose: recon + persistence are strictly read-only; hardening prompts before each change; firewall scripts force you to set ports first.
- Adapt to the actual scored service list the organisers give you.
