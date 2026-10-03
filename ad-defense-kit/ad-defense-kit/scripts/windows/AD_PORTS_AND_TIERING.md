# Domain Owner — Tiering & AD Ports (read before you firewall or RDP anywhere)

You own the DC and you're joining members (mail server, etc.). Two traps kill DC-owning teams:

## TRAP 1 — Credential theft via your own logons (the #1 silent loss)
If you RDP into the mail server (or any member) using a **Domain Admin** account, your DA
ticket/hash sits in that member's LSASS. The moment that member gets popped, the attacker lifts
your DA cred with mimikatz and owns the whole domain — no DC exploit needed. You handed it to them.

**Tiering rule — enforce it hard:**
- **Tier 0 = DC + Domain Admins.** DA accounts log on ONLY to the DC. Never to a member. Never.
- **Tier 1 = member servers (mail etc.).** Administer them with a SEPARATE account that is NOT a
  Domain Admin — a per-server local admin (via LAPS) or a dedicated Tier-1 domain account.
- Put every DA into the **Protected Users** group → no NTLM, no delegation, no credential
  caching, Kerberos-AES only. (`Add-ADGroupMember 'Protected Users' -Members <da>`)
- Enable **LSASS protection** on every box (RunAsPPL=1) so mimikatz can't read LSASS.
- Use GPO **Deny logon** rights: DAs denied logon to Tier 1/2; member-admins denied logon to the DC.

If you remember one thing from this file: **your Domain Admin password never touches the mail server.**

## TRAP 2 — Over-firewalling breaks the domain itself
A default-deny inbound firewall on the DC that only allows "scored ports" will silently kill
domain auth, GPO, and replication for your own members → cascading service failures → lost
availability points, and you'll waste 20 min thinking you got hacked.

**On the DC, allow these INBOUND from your team/member subnet** (in addition to scored ports):

| Port | Proto | Service |
|---|---|---|
| 53 | TCP/UDP | DNS |
| 88 | TCP/UDP | Kerberos |
| 123 | UDP | NTP (time skew > 5 min breaks Kerberos) |
| 135 | TCP | RPC endpoint mapper |
| 389 | TCP/UDP | LDAP |
| 445 | TCP | SMB (GPO, SYSVOL, domain join) |
| 464 | TCP/UDP | Kerberos password change |
| 636 | TCP | LDAPS |
| 3268/3269 | TCP | Global Catalog / GC-SSL |
| 49152-65535 | TCP | RPC dynamic (can pin to a fixed range via registry) |

**On members:** point DNS at the DC's IP (domain join + auth fail without this). Outbound is
usually allow-by-default; don't block outbound to the DC on the ports above.

**Firewall these AD ports to the internal subnet only** — don't expose LDAP/SMB/RPC to the
scoring/attacker network. Scored public services (mail SMTP/IMAP, web) are the only things that
face outward.

## Domain-join sequence (so you don't break things)
1. Set member's DNS → DC IP.
2. Time sync member ↔ DC (`w32tm /resync`); >5 min skew = Kerberos dies.
3. AD ports open DC↔member (above).
4. `Add-Computer -DomainName <dom> -Credential (Get-Credential) -Restart`
5. THEN harden the member (harden.ps1) + let the baseline GPO apply (`gpupdate /force`).
6. Retest scored services after every firewall change.
