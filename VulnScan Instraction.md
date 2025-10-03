**What the script checks (high level)**



Basic system info (OS, uptime, hostname)



Installed hotfixes / patch level (Get-HotFix)



Listening ports and owning processes (netstat equivalent)



Firewall profile \& rules (enabled/disabled/open ports)



SMB configuration \& shares, and whether SMBv1 is enabled



RDP (Remote Desktop) status \& Network Level Authentication (NLA)



Local Admins \& users (accounts in Administrators group)



Running services \& suspicious autostart entries



Scheduled tasks



Weak cipher/TLS registry keys (Schannel/TLS versions) — simple detection



IIS check (if installed) — site list \& bindings



Basic privilege check: whether UAC is disabled, whether PowerShell remoting is enabled



Summary file with “things to check quickly” (unpatched, SMBv1 enabled, RDP open, firewall off, open ports)





**How to use \& interpret results (quick)**



Run as Administrator. It will create C:\\VulnScan\\<timestamp>\\ and a zip with everything.



Check quick\_summary.txt first for urgent warnings (SMBv1 enabled, firewall disabled, RDP on).



Open hotfixes to see missing/installed KBs. If the server lacks recent security updates, prioritize patching.



Look at net\_connections and process\_list to find unexpected services listening on network ports. Cross-check PID → process name.



smb\_shares shows shares and their paths — check for overly permissive shares (Everyone: Full Control).



local\_admins shows who has administrative access — remove unnecessary accounts and service accounts.



scheduled\_tasks and run\_reg\_\* can reveal persistence points if you see unexpected entries.





**Extra defensive tools \& next steps**



For deep vulnerability scanning, use established scanners (authorized use only): Nessus, OpenVAS, Qualys, or Rapid7 Nexpose — these provide CVE-based checks and severity scoring.



For network host scanning from another machine: nmap -sS -sV -O <target\_ip> to detect open ports and services. (Run from a different host.)



Use Microsoft Defender for Endpoint, Sysinternals Autoruns, Process Explorer, and TCPView for deeper runtime analysis.



If you find serious compromise indicators (unknown admin accounts, running suspicious services, evidence of persistent backdoors), isolate the host and do a forensic snapshot before remediation.

