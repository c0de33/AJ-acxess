# monitor.ps1 — leave running in a spare ADMIN PowerShell. Read-only.
# Prints new successful logons, new listeners, and shell-like processes.
Write-Host "[*] monitoring... Ctrl-C to stop" -ForegroundColor Cyan

$seenLogon = (Get-Date)
$prevListen = (Get-NetTCPConnection -State Listen).LocalPort | Sort-Object -Unique

while($true){
  # new successful logons (4624) since last check
  $ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$seenLogon} -EA SilentlyContinue
  foreach($e in $ev){
    $acct = ($e.Properties[5].Value)
    if($acct -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-'){
      Write-Host "[LOGON] $($e.TimeCreated) user=$acct" -ForegroundColor Yellow
    }
  }
  # failed logons (4625) = brute force
  $bf = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$seenLogon} -EA SilentlyContinue
  if($bf){ Write-Host "[BRUTE] $($bf.Count) failed logon(s)" -ForegroundColor Red }
  $seenLogon = (Get-Date)

  # new listeners
  $cur = (Get-NetTCPConnection -State Listen).LocalPort | Sort-Object -Unique
  $new = $cur | Where-Object { $prevListen -notcontains $_ }
  foreach($p in $new){ Write-Host "[NEW LISTENER] port $p" -ForegroundColor Yellow }
  $prevListen = $cur

  # shell-like procs
  Get-Process -EA SilentlyContinue | Where-Object { $_.Name -match 'nc|ncat|powershell|cmd' } |
    Where-Object { $_.Parent.Name -match 'winword|excel|outlook|w3wp|httpd' -EA SilentlyContinue } |
    ForEach-Object { Write-Host "[SUSPECT PROC] $($_.Name) parent=$($_.Parent.Name)" -ForegroundColor Red }

  Start-Sleep 3
}
