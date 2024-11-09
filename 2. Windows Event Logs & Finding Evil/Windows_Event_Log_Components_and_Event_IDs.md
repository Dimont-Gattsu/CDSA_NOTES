## Overview
Each Windows Event Log entry, termed as an "Event," contains the following primary components:

- **Log Name**: The name of the event log (e.g., Application, System, Security).
- **Source**: The software that generated the event.
- **Event ID**: A unique identifier for the event.
- **Task Category**: Describes the purpose or category of the event.
- **Level**: Indicates the severity (Information, Warning, Error, Critical, Verbose).
- **Keywords**: Flags that categorize events, like "Audit Success" or "Audit Failure" for Security logs.
- **User**: The account that was logged in when the event occurred.
- **OpCode**: Identifies the specific operation reported.
- **Logged**: Timestamp for when the event was logged.
- **Computer**: Name of the computer where the event took place.
- **XML Data**: XML format of the event data, containing all above fields and additional details.

The **Keywords** field is particularly useful for filtering and efficiently managing logs, allowing refined searches for specific event types.

---

## Key Windows System Logs

1. **Event ID 1074**: System Shutdown/Restart - Logs when and why the system was shut down or restarted. Abnormal shutdowns can indicate potential malware or unauthorized access.
2. **Event ID 6005**: Event Log Service Start - Marks when the Event Log Service started, often at system boot.
3. **Event ID 6006**: Event Log Service Stop - Indicates Event Log Service stop, typically seen during shutdown.
4. **Event ID 6013**: Windows Uptime - Logs uptime in seconds; unexpected reboots may signal intrusion.
5. **Event ID 7040**: Service Status Change - Logs changes in a service’s startup type; unexpected changes could indicate tampering.

---

## Key Windows Security Logs

1. **Event ID 1102**: Audit Log Cleared - Often associated with intrusion attempts.
2. **Event ID 1116**: Antivirus Malware Detection - Indicates when malware is detected; a rise may suggest an active infection.
3. **Event ID 1118**: Antivirus Remediation Start - Marks the start of malware remediation.
4. **Event ID 1119**: Antivirus Remediation Success - Logs successful malware removal.
5. **Event ID 1120**: Antivirus Remediation Failure - Signifies failed malware removal attempts.
6. **Event ID 4624**: Successful Logon - Records user logins; unusual logins may indicate security risks.
7. **Event ID 4625**: Failed Logon - Failed login attempts, indicating potential brute-force attacks.
8. **Event ID 4648**: Logon with Explicit Credentials - Tracks logons with specific credentials, useful for detecting lateral movement.
9. **Event ID 4656**: Object Handle Request - Logs requests for object handles, aiding in access control monitoring.
10. **Event ID 4672**: Special Privileges Assigned - Super user privileges granted; monitors privilege usage.
11. **Event ID 4698**: Scheduled Task Created - Monitors task creation, often a persistence technique for malware.
12. **Event ID 4700 & 4701**: Scheduled Task Enabled/Disabled - Tracks task status changes, often used by attackers.
13. **Event ID 4702**: Scheduled Task Updated - Logs task updates, potential indicator of malicious changes.
14. **Event ID 4719**: System Audit Policy Change - Records changes to audit policy, potentially covering tracks.
15. **Event ID 4738**: User Account Changed - Logs user account modifications, useful for detecting unauthorized changes.
16. **Event ID 4771**: Kerberos Pre-authentication Failed - Similar to failed logon, specific to Kerberos; may indicate brute force.
17. **Event ID 4776**: Domain Controller Credential Validation - Tracks credential validation attempts by the domain controller.
18. **Event ID 5001**: Antivirus Real-time Protection Configuration Change - Monitors changes in real-time protection settings.
19. **Event ID 5140**: Network Share Accessed - Critical for monitoring unauthorized network access.
20. **Event ID 5142**: Network Share Created - Logs new network shares, potential for data exfiltration or malware spread.
21. **Event ID 5145**: Network Share Access Check - Tracks attempts to access network shares.
22. **Event ID 5157**: Windows Filtering Platform Connection Blocked - Monitors blocked network connections.
23. **Event ID 7045**: Service Installed - Unknown services may suggest malware installation.

---

Monitoring these logs can help identify unauthorized access, potential intrusions, and configuration changes that may signify malicious activity or policy violations.

