## Overview
Effective cybersecurity involves identifying and analyzing malicious events. Using event logs and Sysmon enhances detection of suspicious activity, with Sysmon providing detailed monitoring beyond standard Security Event logs.

---

## Sysmon Basics
Sysmon (System Monitor) is a Windows tool for logging system activity beyond what standard event logs provide. Its main components include:

- **Windows Service**: Monitors system activities.
- **Device Driver**: Captures data for logging.
- **Event Log**: Displays captured activity.

Sysmon offers **unique event IDs** for various types of activity:
- **Event ID 1**: Process Creation
- **Event ID 3**: Network Connection

Sysmon configuration is controlled through an **XML file** that allows inclusion/exclusion of events based on attributes such as process names or IP addresses. Recommended configurations:
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)

**Installation** (requires admin):
```shell
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```
**Applying a Custom Config**:
```shell
C:\Tools\Sysmon> sysmon.exe -c filename.xml
```

---

## Detection Example 1: DLL Hijacking Detection
Sysmon Event ID 7 (Module Load) can be used to detect DLL hijacking. Here’s an approach to detect a hijack:

1. **Modify Sysmon Config**: Use the `sysmonconfig-export.xml` file and ensure module load events are not excluded.
2. **Monitoring**: Event Viewer -> Applications and Services -> Microsoft -> Windows -> Sysmon.

### Indicators of Compromise (IOCs)
- **calc.exe** in writable directory: An unusual directory for a system executable.
- **WININET.dll** loaded outside System32: Indicates hijacking of a trusted DLL.
- **DLL signing status**: Microsoft-signed DLLs being replaced with unsigned versions.

---

## Detection Example 2: Unmanaged PowerShell/C# Injection Detection
Injection of PowerShell or C# into unmanaged processes can indicate malicious behavior. Observing unusual managed code running within unmanaged processes:

1. **Identify .NET Runtime**: Detect clr.dll or clrjit.dll in processes that don’t normally use C#.
2. **Tools**: Process Hacker can be used to view process types and loaded modules.

### Example of Injection:
```powershell
powershell -ep bypass
Import-Module .\Invoke-PSInject.ps1
Invoke-PSInject -ProcId [Process ID] -PoshCode "Write-Host 'Hello, World!'"
```

Sysmon Event ID 7 can reveal DLLs like clr.dll being loaded by unusual processes.

---

## Detection Example 3: Credential Dumping Detection (e.g., Mimikatz)
Credential dumping (e.g., with Mimikatz) often targets LSASS (Local Security Authority Subsystem Service). Mimikatz command `sekurlsa::logonpasswords` dumps credentials from LSASS.

### Detection Method
- **Sysmon Event ID 10 (Process Access)**: Monitors access to LSASS.
- **Indicators**:
  - Random processes accessing LSASS.
  - SourceUser different from TargetUser (e.g., "waldo" accessing SYSTEM's LSASS).
  - Requests for SeDebugPrivileges.

### Sample Mimikatz Execution
```shell
C:\Tools\Mimikatz> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

These detections using Sysmon and event logs provide telemetry for identifying suspicious behavior, though they should be combined with other cybersecurity tools for robust monitoring.

