## Domain Reconnaissance Overview

### Key Concepts
- **Active Directory (AD) Domain Reconnaissance**: A critical phase in the attack lifecycle where attackers gather information on the AD environment, seeking knowledge about its:
	- Architecture, network topology, and security setup.
	- Key assets, including Domain Controllers, user accounts, groups, trust relationships, OUs, and GPOs.
- **Objective**: Identify high-value targets, escalate privileges, and enable lateral movement.

### Recon Techniques with Native Windows Commands
Adversaries may execute commands like `net group` to list Domain Administrators. Common Windows executables used for domain reconnaissance include:
  - `whoami /all`
  - `wmic computersystem get domain`
  - `net user /domain`
  - `net group "Domain Admins" /domain`
  - `arp -a`
  - `nltest /domain_trusts`
  
  **Detection**: Use PowerShell and command-line monitoring to flag unusual command execution.

## Recon with BloodHound/SharpHound

- **BloodHound**: Open-source tool for visualizing AD relationships, trust paths, permissions, and group memberships.
- **SharpHound**: BloodHound’s C# data collector; commonly run with `-c all` to gather comprehensive data.

### BloodHound Detection Methods
- **LDAP Queries**: BloodHound collectors perform many LDAP queries on Domain Controllers.
- **Monitoring Techniques**:
  - **Event 1644**: Windows LDAP performance monitoring, though limited in visibility.
  - **ETW Provider (Microsoft-Windows-LDAP-Client)**: Used with tools like **SilkETW** and **SilkService** (supports Yara rule-based query detection).
  - **Predefined LDAP Filters**: Use filters recommended by Microsoft’s ATP team to recognize common reconnaissance LDAP queries.

---

## Detecting User/Domain Recon with Splunk

**Objective**: Use Splunk queries to detect common reconnaissance activities in a specific time frame, filtering high-volume noise to focus on suspicious events.
#### Detecting Recon Using Native Windows Executables

**Timeframe**: `earliest=1690447949` to `latest=1690450687`

#### Splunk Query
```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) 
  OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

#### Query Breakdown
1. **Filter by Index and Source**:
   - Logs are pulled from Sysmon’s process creation events (`EventID=1`) within a specific timeframe.
2. **Process Name Filter**:
   - Targets processes typically associated with reconnaissance commands or command-line tools.
3. **Aggregate with Stats**:
   - Groups results by `parent_process`, `parent_process_id`, `dest`, and `user`, collecting unique processes and earliest timestamps.
4. **Filter by Process Count**:
   - Flags events where more than three reconnaissance-related processes were run by the same parent process.

---

### Detecting Recon Using BloodHound

**Timeframe**: `earliest=1690195896` to `latest=1690285475`

#### Splunk Query
```spl
index=main earliest=1690195896 latest=1690285475 source="WinEventLog:SilkService-Log"
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

#### Query Breakdown
1. **Filter by Index and Source**:
   - Searches SilkService logs for events within a specified timeframe.
2. **Extract Fields**:
   - `spath` extracts structured fields (e.g., XML data) from `Message`.
3. **Rename and Table**:
   - Renames fields for easier reference and organizes results by key data points.
4. **Filter by LDAP Search Filter**:
   - Detects queries containing `samAccountType=805306368`, often linked to BloodHound’s AD queries.
5. **Statistics Aggregation**:
   - Counts events by `ComputerName`, `ProcessName`, and `ProcessId`, checking for instances with over 10 occurrences.
6. **Convert Timestamp**:
   - Formats `maxTime` to human-readable format for timeline analysis.