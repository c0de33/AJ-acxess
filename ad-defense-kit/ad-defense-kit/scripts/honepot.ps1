# honeypot.ps1 — AD honey account + bait + live watcher.
# WHERE TO RUN WHAT:
#   -Setup   -> on the DC once (creates the honey account + SPN)
#   -Bait    -> on each member/mail box (plants fake creds that point at the honey account)
#   -Watch   -> on the DC, leave running (alerts the instant the honey account is touched)
# Example:  .\honeypot.ps1 -Setup   then   .\honeypot.ps1 -Watch

# ---- parameters: how you call the script decides which part runs ----
param(
  [switch]$Setup,                       # create the honey account on the DC
  [switch]$Bait,                        # plant bait creds on this (member) machine
  [switch]$Watch,                       # run the live detection loop on the DC
  [string]$HoneyUser = "svc_sqlbackup", # the decoy account name (looks like a real service acct)
  [string]$HoneySpn  = "MSSQLSvc/sqlbackup.corp.local:1433"  # SPN that makes it Kerberoastable bait
)

# =====================================================================
# SETUP — run on the DC, once. Creates the decoy account.
# =====================================================================
if ($Setup) {
  Import-Module ActiveDirectory -EA Stop            # load the AD cmdlets (present on a DC)

  # build a 32-byte random password and base64 it -> long + high-entropy on purpose,
  # so even if an attacker Kerberoasts the account, offline cracking of the hash fails.
  $raw = 1..32 | ForEach-Object { Get-Random -Maximum 256 }   # 32 random bytes (0-255)
  $pwPlain = [Convert]::ToBase64String([byte[]]$raw)          # bytes -> a long base64 string
  $pw = ConvertTo-SecureString $pwPlain -AsPlainText -Force   # wrap as a SecureString for AD

  # create the decoy user. Enabled so it can be targeted; pw never expires so it stays put.
  # the Description is deliberately tempting ("service account") to draw attention.
  New-ADUser -Name $HoneyUser -SamAccountName $HoneyUser `
    -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true `
    -Description "SQL backup service account - do not modify"

  # attach an SPN. SPNs on user accounts are what Kerberoasting enumerates, so this is the
  # lure: any attacker running a roast will see this account and request its ticket (-> event 4769).
  setspn -s $HoneySpn $HoneyUser

  # also make it AS-REP roastable: DoesNotRequirePreAuth means its hash can be requested with
  # NO credentials at all, so even an unauthenticated attacker will be tempted to grab it (-> 4768).
  Set-ADAccountControl $HoneyUser -DoesNotRequirePreAuth $true

  # IMPORTANT: give it ZERO real privileges — never add it to Domain Admins or any priv group.
  # If they do manage to use it, it must lead nowhere. The name + SPN do the luring; the account is a dead end.
  Write-Host "[+] Honey account '$HoneyUser' created with SPN '$HoneySpn'. No privileges granted." -ForegroundColor Green
  Write-Host "    Nothing legitimate will ever touch it, so any event referencing it = attacker."
}

# =====================================================================
# BAIT — run on each member/mail box. Plants fake creds pointing at the honey account.
# Catches an attacker who already landed on a host and is looting credentials.
# =====================================================================
if ($Bait) {
  # the bait password is intentionally WRONG — when the attacker tries it, the logon FAILS
  # (event 4625) which still alerts you, and the real honey account stays uncrackable.
  $baitPw = "Summer2019!"

  # 1) drop a fake cached credential into Windows Credential Manager. Credential-dumping tools
  #    (what attackers run after landing) will surface this, and they'll try to use it.
  cmdkey /add:sqlbackup.corp.local /user:"$env:USERDOMAIN\$HoneyUser" /pass:$baitPw

  # 2) drop a plaintext bait file where a looter would look (admin desktop). Same fake creds.
  $baitFile = "$env:PUBLIC\Desktop\db_backup_creds.txt"      # Public desktop = visible to anyone who lands
  "Server: sqlbackup.corp.local`r`nUser: $HoneyUser`r`nPass: $baitPw" | Out-File $baitFile -Encoding ascii

  Write-Host "[+] Bait planted on $env:COMPUTERNAME (Credential Manager + $baitFile)." -ForegroundColor Green
  Write-Host "    Any use of these fake creds triggers a failed logon for the honey account on the DC."
}

# =====================================================================
# WATCH — run on the DC, leave running. Alerts the moment the honey account is touched.
# =====================================================================
if ($Watch) {
  Write-Host "[*] Watching for any activity on honey account '$HoneyUser'... Ctrl-C to stop." -ForegroundColor Cyan
  $since = (Get-Date)                                  # only look at events from now onward

  while ($true) {                                      # loop forever (spare DC window)
    # pull the relevant Kerberos/logon security events since the last check:
    #   4769 = Kerberos service ticket requested  -> someone is Kerberoasting the SPN
    #   4768 = Kerberos TGT requested             -> someone is AS-REP roasting / authing
    #   4624 = logon success                      -> someone actually used looted creds (shouldn't be possible)
    #   4625 = logon failure                      -> someone tried the BAIT password
    $events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4769,4768,4624,4625
                StartTime = $since
              } -EA SilentlyContinue |
              # keep only events that actually name our honey account (zero false positives)
              Where-Object { $_.Message -match $HoneyUser }

    foreach ($e in $events) {                          # for each hit, scream
      Write-Host ("[ALERT] {0}  EventID={1}  -> honey account '{2}' was touched!" `
                   -f $e.TimeCreated, $e.Id, $HoneyUser) -ForegroundColor Red
      # (optional) log it to a file too, so you have a timeline for the incident log
      ("{0},{1},{2}" -f $e.TimeCreated, $e.Id, $HoneyUser) | Add-Content ".\honeypot_hits.csv"
    }

    $since = (Get-Date)                                # advance the window
    Start-Sleep -Seconds 5                             # re-check every 5s
  }
}

# if called with no switch, show usage so you don't accidentally do nothing
if (-not ($Setup -or $Bait -or $Watch)) {
  Write-Host "Usage: .\honeypot.ps1 -Setup   (on DC)  |  -Bait  (on members)  |  -Watch  (on DC)" -ForegroundColor Yellow
}
