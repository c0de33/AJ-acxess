# ad_recon.ps1 — READ-ONLY Active Directory enumeration. Changes nothing.
# Run on the DC (or a member with RSAT). Save it:  .\ad_recon.ps1 | Tee-Object ad_baseline.txt
# If AD module missing on a member:  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory* 
function Section($t){ "`n===== $t =====" }

Section "AM I A DOMAIN CONTROLLER?"
$pt = (Get-CimInstance Win32_OperatingSystem).ProductType   # 1=workstation 2=DC 3=member server
switch($pt){ 2 {"YES — this box is a DC. You can do full AD hardening."} default {"NO — member/workstation (ProductType=$pt). You likely can't reset krbtgt; see member-only notes."} }

try { Import-Module ActiveDirectory -EA Stop; $HasAD=$true } catch { $HasAD=$false; "[!] ActiveDirectory module not available — install RSAT or run on the DC." }
if(-not $HasAD){ return }

Section "DOMAIN / FOREST"
Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,PDCEmulator,InfrastructureMaster
Get-ADForest | Select-Object Name,ForestMode,GlobalCatalogs,SchemaMaster

Section "DOMAIN CONTROLLERS (watch for one you don't recognise = DCShadow / rogue DC)"
Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,OperatingSystem,IsGlobalCatalog | Format-Table -Auto

Section "PRIVILEGED GROUP MEMBERS (anyone unexpected = compromise)"
foreach($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners'){
  try{
    $m = Get-ADGroupMember $g -Recursive -EA Stop | Select-Object -Expand SamAccountName
    "-- $g --  " + ($(if($m){$m -join ', '}else{'(empty)'}))
  }catch{}
}

Section "USERS CREATED IN LAST 2 DAYS"
Get-ADUser -Filter * -Properties whenCreated | Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-2) } |
  Select-Object SamAccountName,whenCreated | Format-Table -Auto

Section "PASSWORDS CHANGED IN LAST 1 DAY"
Get-ADUser -Filter * -Properties PasswordLastSet | Where-Object { $_.PasswordLastSet -gt (Get-Date).AddDays(-1) } |
  Select-Object SamAccountName,PasswordLastSet | Sort-Object PasswordLastSet | Format-Table -Auto

Section "KERBEROASTABLE (user accts with SPN — attacker cracks their pw offline)"
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName |
  Where-Object SamAccountName -ne 'krbtgt' |
  Select-Object SamAccountName,@{n='SPN';e={$_.ServicePrincipalName -join ';'}} | Format-Table -Auto -Wrap

Section "AS-REP ROASTABLE (no Kerberos pre-auth = offline crack, no creds needed)"
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName | Format-Table -Auto

Section "UNCONSTRAINED DELEGATION (compromise = domain takeover)"
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Select-Object Name | Format-Table -Auto
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Select-Object SamAccountName | Format-Table -Auto

Section "CONSTRAINED / RBCD DELEGATION"
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo |
  Select-Object Name,msDS-AllowedToDelegateTo | Format-Table -Auto -Wrap
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Select-Object Name | Format-Table -Auto

Section "adminCount=1 ACCOUNTS (are/were privileged — protected by AdminSDHolder)"
Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount | Select-Object SamAccountName | Format-Table -Auto

Section "KRBTGT PASSWORD LAST SET (basis for Golden Tickets)"
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object SamAccountName,PasswordLastSet

Section "WHO HAS DCSYNC RIGHTS (Replicating Directory Changes on the domain)"
$dn=(Get-ADDomain).DistinguishedName
$guid=[GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
(Get-Acl "AD:$dn").Access | Where-Object { $_.ObjectType -eq $guid } |
  Select-Object IdentityReference,ActiveDirectoryRights | Format-Table -Auto

Section "GPOs (check for malicious startup scripts / scheduled tasks / added admins)"
Get-GPO -All -EA SilentlyContinue | Select-Object DisplayName,ModificationTime | Sort-Object ModificationTime -Descending | Format-Table -Auto

"`nad_recon done — flag anything you didn't put there, then hit ad_harden.ps1."
