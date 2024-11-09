# Overview
Event Tracing for Windows (ETW) offers a rich data source for detecting and analyzing suspicious activities, with detailed visibility into system events. Below are some detection scenarios that utilize ETW's capabilities for enhanced security insights.

---

## Detection Example 1: Detecting Strange Parent-Child Relationships

Unusual parent-child process relationships, such as "calc.exe" spawning "cmd.exe", can indicate malicious activity. Observing such anomalies helps in identifying possible threats. **Process Hacker** provides a way to explore these relationships within Windows.

### Attack Simulation - Parent PID Spoofing
- Attackers can simulate a strange parent-child relationship using Parent PID Spoofing.
- Example command:
  ```powershell
  PS C:\Tools\psgetsystem> powershell -ep bypass
  Import-Module .\psgetsys.ps1 
  [MyProcess]::CreateProcessFromParent([Process ID], "C:\Windows\System32\cmd.exe", "")
  ```

Using ETW with **SilkETW** can enhance detection by providing accurate telemetry beyond what Sysmon logs alone may capture.

### Using SilkETW
Run SilkETW to capture accurate process relationships:
```shell
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json
```

---

## Detection Example 2: Detecting Malicious .NET Assembly Loading

Threat actors increasingly use .NET assemblies loaded directly in memory, bypassing disk-based detection. Known as "Bring Your Own Land" (BYOL), this tactic leverages the .NET framework pre-installed on Windows.

### Attack Simulation - Malicious .NET Assembly Load
- Executing a .NET assembly like **Seatbelt** from memory loads .NET-related DLLs (clr.dll, mscoree.dll).
- Sysmon Event ID 7 can track these DLL loads, but Sysmon alone may not capture all assembly details.

### Using ETW with SilkETW for Deeper Insights
To monitor .NET runtime activity, capture events from the **Microsoft-Windows-DotNETRuntime** provider with SilkETW:
```shell
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```

**Selected Keywords in Use**:
- **JitKeyword**: Tracks Just-In-Time (JIT) compilation events.
- **InteropKeyword**: Logs managed-to-unmanaged code interactions.
- **LoaderKeyword**: Monitors assembly loading activities.
- **NGenKeyword**: Captures precompiled .NET assembly operations.

These keywords provide focused telemetry on .NET activity, aiding in the detection of in-memory .NET execution, which traditional logs might overlook.

---

Leveraging ETW and targeted providers like **Microsoft-Windows-Kernel-Process** and **Microsoft-Windows-DotNETRuntime** enables security teams to detect and respond to advanced threats effectively, including unusual process relationships and in-memory .NET assembly loads.

---

### References
- [SilkETW blog post on .NET-based malware detection](https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf)
