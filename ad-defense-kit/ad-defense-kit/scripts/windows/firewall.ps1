# firewall.ps1 — default-deny inbound, allow only what you list.
#
#   !!! EDIT THE VARS BELOW BEFORE RUNNING !!!
#   !!! KEEP AN RDP/CONSOLE SESSION OPEN — allow RDP from your IP FIRST !!!
#
# Run in ADMIN PowerShell. Wrong values = you drop RDP or a scored service.

# ---- EDIT ME ---------------------------------------------------------
$MyIP        = "10.0.0.100"      # YOUR machine's IP (for RDP allow-list)
$RdpPort     = 3389
$ScoredPorts = @(80, 443)        # ports scored for availability — ADD YOURS
$AllowICMP   = $true             # scoring engine often pings
# ---------------------------------------------------------------------

Write-Host "MyIP=$MyIP  RDP=$RdpPort  Scored=$($ScoredPorts -join ',')" -ForegroundColor Cyan
Read-Host "Correct? Ctrl-C to abort, Enter to apply"

# 1) allow rules FIRST (so enabling block doesn't cut you off)
New-NetFirewallRule -DisplayName "ADM-RDP" -Direction Inbound -Protocol TCP `
  -LocalPort $RdpPort -RemoteAddress $MyIP -Action Allow -EA SilentlyContinue | Out-Null
foreach($p in $ScoredPorts){
  New-NetFirewallRule -DisplayName "SCORED-$p" -Direction Inbound -Protocol TCP `
    -LocalPort $p -Action Allow -EA SilentlyContinue | Out-Null
}
if($AllowICMP){
  New-NetFirewallRule -DisplayName "ALLOW-ICMP" -Protocol ICMPv4 -IcmpType 8 `
    -Direction Inbound -Action Allow -EA SilentlyContinue | Out-Null
}

# 2) now flip profiles to default-block inbound
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

Write-Host "`n[OK] Firewall applied. Active allow rules:" -ForegroundColor Green
Get-NetFirewallRule -Action Allow -Enabled True |
  Where-Object DisplayName -match 'ADM-|SCORED-|ALLOW-' |
  Select-Object DisplayName | Format-Table -Auto

Write-Host "NOW test every scored port from another host. If one is down, add it above + re-run." -ForegroundColor Yellow
