# harden.ps1 — CAREFUL Windows hardening. Prompts before each change.
# Does NOT touch the firewall (use firewall.ps1). Run in ADMIN PowerShell.
function Ask($m){ (Read-Host "$m [y/N]") -match '^[yY]' }

Write-Host "== 1. Rotate all enabled local-user passwords ==" -ForegroundColor Cyan
Write-Host "   writes new_creds.txt — MOVE IT OFF THE BOX AFTER."
if(Ask "Rotate now?"){
  "" | Out-File new_creds.txt
  Get-LocalUser | Where-Object Enabled | ForEach-Object {
    $pw = "Cmp!" + -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 9 | ForEach-Object {[char]$_})
    try{
      $sec = ConvertTo-SecureString $pw -AsPlainText -Force
      Set-LocalUser -Name $_.Name -Password $sec
      "$($_.Name) : $pw" | Add-Content new_creds.txt
      Write-Host "   set $($_.Name)"
    }catch{ Write-Host "   FAILED $($_.Name): $_" -ForegroundColor Red }
  }
  Get-Content new_creds.txt
}

Write-Host "`n== 2. Disable Guest ==" -ForegroundColor Cyan
if(Ask "Disable Guest?"){ Disable-LocalUser -Name Guest -EA SilentlyContinue; Write-Host "   done" }

Write-Host "`n== 3. Show admins (remove unknowns manually) ==" -ForegroundColor Cyan
Get-LocalGroupMember Administrators | Select-Object Name,PrincipalSource | Format-Table -Auto
Write-Host "   Remove-LocalGroupMember Administrators -Member <name>"

Write-Host "`n== 4. Password policy ==" -ForegroundColor Cyan
if(Ask "Set min length 12?"){ net accounts /minpwlen:12 /uniquepw:5 }

Write-Host "`n== 5. Disable SMBv1 ==" -ForegroundColor Cyan
if(Ask "Disable SMBv1 (EternalBlue surface)?"){
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -EA SilentlyContinue
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -EA SilentlyContinue
  Write-Host "   done"
}

Write-Host "`n== 6. Logging ==" -ForegroundColor Cyan
if(Ask "Grow Security log to 100MB + enable PS script-block logging?"){
  wevtutil sl Security /ms:104857600
  $p='HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
  New-Item $p -Force | Out-Null
  Set-ItemProperty $p EnableScriptBlockLogging 1
  Write-Host "   done"
}

Write-Host "`n== 7. Backup key configs ==" -ForegroundColor Cyan
if(Ask "Export firewall rules + services list to .\backup ?"){
  New-Item -ItemType Directory backup -Force | Out-Null
  netsh advfirewall export .\backup\fw.wfw | Out-Null
  Get-Service | Export-Csv .\backup\services.csv -NoTypeInformation
  Write-Host "   -> .\backup\"
}

Write-Host "`n[OK] harden.ps1 done. Firewall is separate: run firewall.ps1." -ForegroundColor Green
