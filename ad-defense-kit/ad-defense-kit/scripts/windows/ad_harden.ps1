# ad_harden.ps1 — CAREFUL AD hardening. Run on the DC as Domain Admin. Prompts before each change.
# ONLY run the krbtgt reset if you OWN the DC. On a member-only box, skip to the notes at the bottom.
Import-Module ActiveDirectory -EA Stop
function Ask($m){ (Read-Host "$m [y/N]") -match '^[yY]' }
function RandPw(){ $b=New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) }

Write-Host "== 1. Audit privileged groups — remove members you didn't add ==" -ForegroundColor Cyan
foreach($g in 'Domain Admins','Enterprise Admins','Schema Admins','Account Operators','Backup Operators','DnsAdmins'){
  $m = Get-ADGroupMember $g -Recursive -EA SilentlyContinue | Select-Object -Expand SamAccountName
  Write-Host "  $g : $($m -join ', ')"
}
Write-Host "  Remove:  Remove-ADGroupMember 'Domain Admins' -Members <sam> -Confirm:`$false" -ForegroundColor DarkGray

Write-Host "`n== 2. Reset ALL Domain Admin passwords (unique) ==" -ForegroundColor Cyan
Write-Host "   writes ad_creds.txt — MOVE OFF THE BOX AFTER."
if(Ask "Reset every Domain Admin member's password?"){
  "" | Out-File ad_creds.txt
  Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object objectClass -eq 'user' | ForEach-Object {
    $pw = RandPw
    try{
      Set-ADAccountPassword -Identity $_.SamAccountName -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
      "$($_.SamAccountName) : $pw" | Add-Content ad_creds.txt
      Write-Host "   reset $($_.SamAccountName)"
    }catch{ Write-Host "   FAILED $($_.SamAccountName): $_" -ForegroundColor Red }
  }
}

Write-Host "`n== 3. KRBTGT DOUBLE-RESET  (kills Golden Tickets) ==" -ForegroundColor Yellow
Write-Host @"
   Why twice: a Golden Ticket is signed with the krbtgt hash the attacker stole via DCSync.
   krbtgt keeps current(N) + previous(N-1). One reset -> stolen hash becomes N-1, still valid.
   TWO resets -> stolen hash is N-2 -> forged tickets die.
   Cost: existing Kerberos tickets get invalidated; brief auth disruption. Gap between resets
   lets legit tickets renew + (multi-DC) replicate. Single-DC comp: ~10 min gap is plenty.
"@ -ForegroundColor DarkYellow
if(Ask "Do krbtgt reset #1 now?"){
  Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (RandPw) -AsPlainText -Force)
  Write-Host "   reset #1 done." -ForegroundColor Green
  try{ repadmin /syncall /AdeP | Out-Null }catch{}
  Write-Host "   >>> WAIT ~10 min (or full replication if multi-DC), verify services still auth, THEN run reset #2." -ForegroundColor Yellow
  if(Ask "Already waited — do reset #2 NOW?"){
    Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (RandPw) -AsPlainText -Force)
    try{ repadmin /syncall /AdeP | Out-Null }catch{}
    Write-Host "   reset #2 done — Golden Tickets from stolen hash are now dead." -ForegroundColor Green
  } else { Write-Host "   remember to re-run and do reset #2 after the wait." -ForegroundColor Yellow }
}

Write-Host "`n== 4. Reset service-account passwords (kills Silver Tickets) ==" -ForegroundColor Cyan
Write-Host "   Any account with an SPN. Resetting invalidates forged service tickets."
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName |
  Where-Object SamAccountName -ne 'krbtgt' | Select-Object SamAccountName | Format-Table -Auto
Write-Host "   Reset each with Set-ADAccountPassword (careful — may need to update the service config)."

Write-Host "`n== 5. AdminSDHolder ACL — backdoor ACE check ==" -ForegroundColor Cyan
$dn=(Get-ADDomain).DistinguishedName
Write-Host "   Review for IdentityReferences that shouldn't have rights:"
(Get-Acl "AD:CN=AdminSDHolder,CN=System,$dn").Access |
  Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType | Format-Table -Auto

Write-Host "`n== 6. DCSync rights holders (should be only DCs / admins) ==" -ForegroundColor Cyan
$guid=[GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
(Get-Acl "AD:$dn").Access | Where-Object { $_.ObjectType -eq $guid } |
  Select-Object IdentityReference,AccessControlType | Format-Table -Auto
Write-Host "   Unexpected identity here = DCSync backdoor. Remove its ACE."

Write-Host "`n== 7. SIDHistory anomalies (injected privilege) ==" -ForegroundColor Cyan
Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory |
  Select-Object SamAccountName,SIDHistory | Format-Table -Auto

Write-Host "`n== 8. Disable a suspect account ==" -ForegroundColor Cyan
Write-Host "   Disable-ADAccount -Identity <sam>   (don't disable YOUR account)"

Write-Host "`n[OK] ad_harden done." -ForegroundColor Green
Write-Host @"

MEMBER-ONLY BOX (you don't control the DC):
  - You CAN'T reset krbtgt / domain accounts. The DC is a shared surface.
  - Remove domain users from the LOCAL Administrators group where possible.
  - Restrict interactive/RDP logon: only your team's accounts (secpol > User Rights Assignment).
  - Watch for Domain Admin logons to your box (event 4672 + 4624 logontype 10/3).
  - If LAPS is deployed, local admin pw is managed — don't fight it; use it.
  - Assume any domain cred can hit you; keep monitor.ps1 + persistence.ps1 running.
"@ -ForegroundColor DarkCyan
