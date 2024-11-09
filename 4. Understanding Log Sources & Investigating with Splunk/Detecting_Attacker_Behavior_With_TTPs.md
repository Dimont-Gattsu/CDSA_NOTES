In cybersecurity, identifying and monitoring for attacker tactics, techniques, and procedures (TTPs) are essential for effective threat detection. This process involves recognizing patterns that indicate either known malicious behavior or anomalies that deviate from the norm. Detection strategies in Splunk involve two key approaches:

1. **Using Known TTPs**: Leveraging our understanding of specific attack behaviors to create detection rules.
2. **Anomaly Detection**: Using statistical analysis to identify unusual patterns without prior knowledge of specific attacks.

Together, these approaches provide a comprehensive toolkit for recognizing and responding to various threats. Regularly tuning queries and thresholds in both methods enhances accuracy and reduces false positives.

## Crafting SPL Searches Based on Known TTPs

Using known TTPs as a foundation, detection queries are crafted to match behaviors associated with specific threats. Examples of detection searches following this approach are outlined below.

### Example: Detecting Reconnaissance Activities with Native Windows Binaries
Attackers often use native Windows binaries like `net.exe` and `ipconfig.exe` for reconnaissance. Sysmon Event ID 1 can help identify such actions.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\ipconfig.exe OR Image=*\net.exe OR Image=*\whoami.exe OR Image=*\netstat.exe OR Image=*\nbtstat.exe OR Image=*\hostname.exe OR Image=*\tasklist.exe | stats count by Image,CommandLine | sort - count
```

### Example: Detecting Malicious Payload Requests Hosted on Reputable Domains
Attackers may host malicious tools on platforms like githubusercontent.com. Sysmon Event ID 22 can identify these requests.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22 QueryName="*github*" | stats count by Image, QueryName
```

### Example: Detecting PsExec Usage
PsExec, a powerful tool for remote command execution, is frequently leveraged by attackers. Relevant Sysmon events include Event ID 13, Event ID 11, and Event ID 18.

#### Case 1: Sysmon Event ID 13
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\Windows\system32\services.exe" TargetObject="HKLM\System\CurrentControlSet\Services\*\ImagePath" | rex field=Details "(?<reg_file_name>[^\\]+)$" | eval file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
```

#### Case 2: Sysmon Event ID 11
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename
```

#### Case 3: Sysmon Event ID 18
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName
```

### Example: Detecting Archive File Use for Data Transfer
Attackers may use zip, rar, or 7z files for tool transfer or data exfiltration.

```spl
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count
```

### Example: Detecting Payload Downloads via PowerShell or Edge
Attackers often use PowerShell or web browsers for downloads.

#### PowerShell Downloads
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" | stats count by Image, TargetFilename | sort + count
```

#### Edge Downloads with Zone Identifier
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" | stats count by TargetFilename | sort + count
```

### Example: Detecting Execution from Suspicious Locations
```spl
index="main" EventCode=1 | regex Image="C:\\Users\\.*\\Downloads\\.*" | stats count by Image
```

### Example: Detecting Executables Created Outside Windows Directory
```spl
index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\windows\*" | stats count by User, TargetFilename | sort + count
```

### Example: Detecting Misspelled Binaries (e.g., PSEXESVC.exe)
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) | table Image, CommandLine, ParentImage, ParentCommandLine
```

### Example: Detecting Non-standard Ports in Communication
```spl
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count
```

By employing TTP-based SPL searches, we can detect known attack patterns in our network. However, focusing only on known TTPs has limitations, as attackers often evolve their techniques to evade detection.

## Conclusion
Creating detections based on known TTPs enables faster identification of familiar threats, while anomaly detection surfaces previously unknown risks. Together, these strategies provide a strong foundation for detecting malicious activity in Splunk, though continuous tuning is required to adapt to evolving attacker tactics.
