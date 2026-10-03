# recon.ps1 — READ-ONLY baseline of a Windows box. Changes nothing.
# Run in an ADMIN PowerShell FIRST:  .\recon.ps1 | Tee-Object baseline_win.txt
function Section($t){ "`n===== $t =====" }

Section "HOST / OS / TIME"
hostname; (Get-CimInstance Win32_OperatingSystem).Caption; Get-Date

Section "LOCAL USERS"
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet | Format-Table -Auto

Section "ADMINISTRATORS GROUP (remove anyone you didn't add)"
Get-LocalGroupMember Administrators | Select-Object Name,PrincipalSource | Format-Table -Auto

Section "LISTENING PORTS -> PROCESS"
Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
  Select-Object LocalAddress,LocalPort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
  Format-Table -Auto

Section "ESTABLISHED CONNECTIONS"
Get-NetTCPConnection -State Established |
  Select-Object LocalPort,RemoteAddress,RemotePort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
  Format-Table -Auto

Section "SERVICES (running) — watch for binaries in temp/appdata"
Get-CimInstance Win32_Service | Where-Object State -eq Running |
  Select-Object Name,StartMode,PathName | Format-Table -Auto -Wrap

Section "SCHEDULED TASKS (enabled)"
Get-ScheduledTask | Where-Object State -ne Disabled |
  Select-Object TaskName,TaskPath | Format-Table -Auto

Section "RUN KEYS (machine + user)"
"HKLM:"; Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue
"HKCU:"; Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -EA SilentlyContinue

Section "STARTUP FOLDERS"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue

Section "FIREWALL STATE"
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -Auto

Section "SHARES"
Get-SmbShare | Select-Object Name,Path,Description | Format-Table -Auto

"`nrecon done."
