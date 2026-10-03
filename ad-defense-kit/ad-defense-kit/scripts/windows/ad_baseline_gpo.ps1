# ad_baseline_gpo.ps1 — push a hardening baseline to EVERY joined member at once, from the DC.
# Run on the DC as Domain Admin. Creates one GPO linked at the domain root + sets domain policy.
# Members pick it up on next gpupdate / reboot. Prompts before applying.
Import-Module ActiveDirectory, GroupPolicy -EA Stop
function Ask($m){ (Read-Host "$m [y/N]") -match '^[yY]' }
$domDN = (Get-ADDomain).DistinguishedName

Write-Host "== 1. Domain password + lockout policy ==" -ForegroundColor Cyan
if(Ask "Set min-len 12, lockout after 5 bad tries?"){
  Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot `
    -MinPasswordLength 12 -ComplexityEnabled $true -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 15) -LockoutObservationWindow (New-TimeSpan -Minutes 15)
  Write-Host "   done"
}

Write-Host "`n== 2. Put Domain Admins into Protected Users (kills NTLM/deleg/cred-cache for them) ==" -ForegroundColor Cyan
if(Ask "Add all Domain Admins to Protected Users?"){
  Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object objectClass -eq 'user' | ForEach-Object {
    Add-ADGroupMember 'Protected Users' -Members $_.SamAccountName -EA SilentlyContinue
    Write-Host "   + $($_.SamAccountName)"
  }
  Write-Host "   NOTE: Protected Users can't use NTLM — make sure services they run use Kerberos."
}

Write-Host "`n== 3. Create + link the hardening GPO (applies to all members) ==" -ForegroundColor Cyan
if(Ask "Create GPO 'Team-Baseline-Hardening' and link at domain root?"){
  $g = New-GPO -Name 'Team-Baseline-Hardening' -EA SilentlyContinue
  if(-not $g){ $g = Get-GPO -Name 'Team-Baseline-Hardening' }
  New-GPLink -Name $g.DisplayName -Target $domDN -LinkEnabled Yes -EA SilentlyContinue | Out-Null

  $set = { param($k,$v,$t,$val) Set-GPRegistryValue -Name 'Team-Baseline-Hardening' -Key $k -ValueName $v -Type $t -Value $val | Out-Null }

  # kill mimikatz LSASS read
  & $set 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' DWord 1
  # WDigest cleartext off
  & $set 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' DWord 0
  # SMBv1 server off
  & $set 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' DWord 0
  # LLMNR off (stops responder-style poisoning)
  & $set 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' DWord 0
  # SMB signing required (stops relay)
  & $set 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' DWord 1
  & $set 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' DWord 1
  # cache fewer logons
  & $set 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' String '1'
  Write-Host "   GPO set: RunAsPPL, WDigest off, SMBv1 off, LLMNR off, SMB signing, cred cache=1"
  Write-Host "   Run 'gpupdate /force' on members (or reboot). RunAsPPL needs a reboot."
}

Write-Host "`n== 4. Audit policy (so you can SEE attacks) ==" -ForegroundColor Cyan
if(Ask "Enable key audit subcategories on the DC now (auditpol)?"){
  auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
  Write-Host "   done. For members, add these via the GPO's Advanced Audit Policy in GPMC."
}

Write-Host @"

MANUAL in GPMC (PowerShell can't set User Rights Assignment cleanly):
  Computer Config > Policies > Windows Settings > Security Settings > Local Policies >
  User Rights Assignment:
    - Deny log on locally / through RDP  -> Domain Admins    (keeps DA creds off members)
    - Deny log on locally / through RDP  -> your member-admin (keeps them off the DC)
  This is the tiering enforcement. See AD_PORTS_AND_TIERING.md.

LAPS (local-admin password rotation on members):
  Windows LAPS is built into current Windows: Update-LapsADSchema ; then set the LAPS GPO.
"@ -ForegroundColor DarkCyan

Write-Host "`n[OK] baseline done." -ForegroundColor Green
