## Summary

The "Stuxbot" cybercrime collective has initiated a broad phishing campaign, primarily targeting Microsoft Windows users without any specific targeting strategy. Their objective appears to be espionage, aiming for system control and escalation rather than financial gain.

- **Platforms in Crosshairs:** Microsoft Windows
- **Threatened Entities:** Windows Users
- **Potential Impact:** Complete computer takeover / Domain escalation
- **Risk Level:** Critical

## Attack Tactics and Techniques

Stuxbot utilizes opportunistic phishing for initial access, leveraging breached email databases and publicly available data. The group has a modular Remote Access Tool (RAT) for espionage and maintains persistence with disk-based EXE files.

### Lifecycle Overview

1. **Initial Breach**: Phishing emails with links to OneNote files containing a malicious batch file.
2. **RAT Characteristics**: The modular RAT includes screen capture, Mimikatz, and interactive CMD tools.
3. **Persistence**: EXE files deployed on the disk.
4. **Lateral Movement**: Uses Microsoft-signed PsExec and WinRM for internal propagation.

### Indicators of Compromise (IOCs)

**OneNote File**:
- `https://transfer.sh/get/kNxU7/invoice.one`
- `https://mega.io/dl9o1Dz/invoice.one`

**Staging Entity (PowerShell Script)**:
- `https://pastebin.com/raw/AvHtdKb2`
- `https://pastebin.com/raw/gj58DKz`

**C&C Nodes**:
- `91.90.213.14:443`
- `103.248.70.64:443`
- `141.98.6.59:443`

**SHA256 Hashes**:
- `226A723FFB4A91D9950A8B266167C5B354AB0DB1DC225578494917FE53867EF2`
- `C346077DAD0342592DB753FE2AB36D2F9F1C76E55CF8556FE5CDA92897E99C7E`
- `018D37CBD3878258C29DB3BC3F2988B6AE688843801B9ABC28E6151141AB66D4`

## Hunting For Stuxbot With The Elastic Stack

The hunt for Stuxbot utilizes the Elastic Stack, with logs from multiple sources, including Windows, Sysmon, PowerShell, and Zeek.

### Available Data
- **Windows audit logs** under `windows*`
- **Sysmon logs** under `windows*`
- **PowerShell logs** under `windows*`
- **Zeek logs** under `zeek*`

Our search covers logs dating back to March 2023, containing approximately 118,975 entries in Windows logs and 332,261 in Zeek logs.

### Environment Overview
The company setup includes around 200 employees with primary use of Office applications, Gmail for email, and Microsoft Edge for browsing. TeamViewer is used for remote support, and Active Directory manages devices. 

## Hunting Activities

1. **Invoice File Download Detection**
   - Query: `event.code:15 AND file.name:*invoice.one`
   - Result: Identified "invoice.one" file download by user Bob on 26th March 2023 at 22:05:47.

2. **File Execution Detection**
   - Query: `event.code:11 AND file.name:invoice.one*`
   - Hostname: `WS001` with IP `192.168.28.130`.
   - Further checks reveal `cmd.exe` initiated the execution of "invoice.bat" and PowerShell from Pastebin.

3. **Network Activity Review**
   - Query: `source.ip:192.168.28.130 AND dns.question.name:*`
   - Findings: File download from `file.io` verified with DNS and IP matches.

4. **Command Execution Tracing**
   - OneNote accessed "invoice.one" file and initiated `cmd.exe`.
   - PowerShell script download from Pastebin was detected with suspicious arguments.

5. **Persistence Mechanism Check**
   - Query: `process.name:"default.exe"`
   - Findings: "default.exe" initiated DNS resolutions and network connections consistent with C2 behavior.

6. **Further Lateral Movement Detection**
   - "SharpHound.exe" used for Active Directory reconnaissance on both `WS001` and `PKI`.
   - `svc-sql1` account credentials likely compromised.

### Conclusion and Next Steps
Stuxbot’s activities have been mapped through multiple stages from initial access to lateral movement and persistence. The compromised `svc-sql1` account suggests critical exposure within the organization. Immediate steps for containment and further analysis are recommended to mitigate ongoing risks.
