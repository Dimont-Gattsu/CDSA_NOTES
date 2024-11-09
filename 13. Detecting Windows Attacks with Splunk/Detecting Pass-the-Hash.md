## Overview of Pass-the-Hash

**Pass-the-Hash (PtH)** is a technique that allows attackers to authenticate to systems using the NTLM hash of a password instead of the plaintext password. It exploits how Windows stores password hashes in memory, making it possible to capture and reuse these hashes for lateral movement.

### Pass-the-Hash Attack Steps:
1. **Hash Extraction**: The attacker, often using tools like Mimikatz, extracts the NTLM hash from memory (usually from the `lsass.exe` process).
2. **Authentication with Hash**: Using the NTLM hash, the attacker can authenticate to network resources as the compromised user.
3. **Lateral Movement**: The attacker gains unauthorized access to networked systems or resources without knowing the plaintext password.

## Detection Opportunities for Pass-the-Hash

To detect PtH attacks, it is essential to monitor for unusual logon events and suspicious process access patterns, specifically targeting:
- **Event ID 4624**: Logon event, particularly with LogonType 9 (NewCredentials) and Logon_Process of `seclogo`, which may indicate alternate credentials.
- **Sysmon Event ID 10**: Process access events, focusing on attempts to access `lsass.exe`, where tools like Mimikatz interact with LSASS to dump password hashes.

## Detecting Pass-the-Hash With Splunk

The following Splunk searches help identify PtH attacks by correlating security logon events with Sysmon process access events.

---

### Example 1: Detecting Alternate Credentials Logon

**Description**: Searches for logon events with LogonType 9 (NewCredentials) and Logon_Process `seclogo`, which may indicate the use of alternate credentials.

**Timeframe**: `earliest=1690450689 latest=1690451116`

```spl
index=main earliest=1690450689 latest=1690451116 source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

---

### Example 2: Detecting Pass-the-Hash with LSASS Access

**Description**: Enhances the detection of PtH by combining LogonType 9 logons with Sysmon Event ID 10, which flags suspicious access to `lsass.exe`. This approach associates unauthorized process access with potential credential usage for lateral movement.

**Timeframe**: `earliest=1690450689 latest=1690451116`

```spl
index=main earliest=1690450689 latest=1690451116 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") 
OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

### Explanation of Key Search Components

1. **Event Filtering**: 
   - The query isolates Sysmon events where `lsass.exe` is accessed (EventCode 10) but excludes legitimate processes like `MsMpEng.exe`.
   - It also includes logon events with EventCode 4624, LogonType 9, and Logon_Process `seclogo`, indicating alternate credentials.

2. **Transaction Command**: 
   - **Purpose**: Links process access events targeting `lsass.exe` with logon events within a brief time span.
   - **Configuration**: Groups events based on the `host` field, with `maxspan=1m`, starting with EventCode 10 (indicating lsass access) and ending with EventCode 4624 (a logon).

3. **Stats Aggregation**:
   - **Purpose**: Summarizes the detection results to show unique combinations of suspicious events by IP, user, and process.
   - **Output Fields**: Filters and organizes key fields, such as `Computer`, `SourceImage`, `SourceProcessId`, and `Network_Account_Name`.