# persistence.ps1 — READ-ONLY hunt for attacker persistence. Changes nothing.
# Re-run every ~30 min. Verify hits, remove manually, log in Incident Log.
function Flag($t){ "`n### $t ###" }
$susp = 'temp|appdata|\\users\\public|\.ps1|-enc|-encodedcommand|downloadstring|iex|frombase64'

Flag "Unexpected admins"
Get-LocalGroupMember Administrators | Select-Object Name,PrincipalSource | Format-Table -Auto

Flag "Recently created local users"
Get-LocalUser | Sort-Object PasswordLastSet -Descending |
  Select-Object Name,Enabled,PasswordLastSet -First 10 | Format-Table -Auto

Flag "Scheduled tasks with suspicious actions"
Get-ScheduledTask | ForEach-Object {
  $a = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' '
  if ($a -match $susp) { [pscustomobject]@{Task=$_.TaskName; Path=$_.TaskPath; Action=$a} }
} | Format-Table -Auto -Wrap

Flag "Services pointing at suspicious paths"
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match $susp } |
  Select-Object Name,State,PathName | Format-Table -Auto -Wrap

Flag "Run keys (machine + user + RunOnce)"
foreach($k in @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')){
  "-- $k --"; Get-ItemProperty $k -EA SilentlyContinue | Format-List
}

Flag "WMI event-consumer persistence (fileless)"
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -EA SilentlyContinue
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -EA SilentlyContinue |
  Select-Object Name,CommandLineTemplate

Flag "Startup folders"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue

Flag "New services event (7045) last 24h"
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-1)} -EA SilentlyContinue |
  Select-Object TimeCreated,Message | Format-Table -Auto -Wrap

Flag "Suspicious listeners (shell-like processes)"
Get-NetTCPConnection -State Listen |
  Select-Object LocalPort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
  Where-Object { $_.Proc -match 'powershell|cmd|nc|ncat|python' } | Format-Table -Auto

"`npersistence hunt done."
