## Overview
Event Tracing for Windows (ETW) is a high-performance event tracing tool in Windows, enabling comprehensive logging from both user-mode applications and kernel-mode device drivers. ETW facilitates the dynamic generation, collection, and analysis of system events, providing telemetry that spans system calls, process creation/termination, network activity, file/registry changes, and more. ETW’s data offers invaluable context for detecting anomalies, investigating security incidents, and performing forensic analysis.

---

## Key Components of ETW

1. **Controllers**: Responsible for managing ETW sessions, including starting, stopping, and enabling providers.
   - Example: **logman.exe** is a common controller for ETW activities.

2. **Providers**: Generate specific types of events within ETW, based on four primary types:
   - **MOF Providers**: Use Managed Object Format for flexible event generation.
   - **WPP Providers**: Leverage source code annotations for kernel-mode tracing.
   - **Manifest-based Providers**: Use XML manifests to define event structure.
   - **TraceLogging Providers**: Simplified providers for recent Windows versions.

3. **Consumers**: Subscribe to and process specific ETW events, often saved in .ETL files for long-term storage.

4. **Channels**: Logical containers that organize events by characteristics, allowing consumers to selectively subscribe.

5. **ETL Files**: Event Trace Log (ETL) files are durable storage formats for offline analysis, archiving, and investigations.

---

## Interacting with ETW

### Managing ETW Sessions
- **Logman Utility**: Used to create, start, stop, and query ETW sessions.
  ```shell
  C:\Tools> logman.exe query -ets
  ```
  This command provides details about active ETW sessions.

- **Querying Session Details**: Inspecting session details (Name, Log Size, Providers) can offer incident responders critical context for investigations.
  ```shell
  C:\Tools> logman.exe query "EventLog-System" -ets
  ```

- **Provider Listing**: List all available providers on the system.
  ```shell
  C:\Tools> logman.exe query providers
  ```

### GUI Alternatives
- **Performance Monitor**: Visualizes active ETW sessions, with modification options for adding/removing providers.
- **EtwExplorer**: Provides metadata insights into ETW providers.

---

## Useful ETW Providers

- **Microsoft-Windows-Kernel-Process**: Monitors process activities like injection or hollowing.
- **Microsoft-Windows-Kernel-File**: Detects file modifications related to exfiltration or ransomware.
- **Microsoft-Windows-Kernel-Network**: Captures network activities to detect unauthorized connections.
- **Microsoft-Windows-SMBClient/SMBServer**: Tracks SMB traffic, potentially useful for detecting lateral movement.
- **Microsoft-Windows-DotNETRuntime**: Monitors .NET runtime for suspicious application executions.
- **Microsoft-Windows-PowerShell**: Essential for tracking PowerShell execution and command logging.
- **Microsoft-Windows-TerminalServices-LocalSessionManager**: Observes RDP activity, useful for detecting remote desktop intrusions.

---

## Restricted Providers

**Microsoft-Windows-Threat-Intelligence**: 
A high-value, restricted provider requiring privileged access (PPL - Protected Process Light) for telemetry on sophisticated threats. This provider is critical in DFIR operations and may reveal granular threat data, origins, interactions, and impacts. Privileged access enables capturing detailed logs of advanced threats, though some workarounds exist.

---

ETW is an advanced telemetry source with minimal system performance impact, suitable for real-time monitoring and continuous security assessment. Future sections will cover leveraging ETW for attack detection beyond Sysmon’s capabilities.

---

### References
- [ETW Primer](https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf)
- [Comprehensive ETW Guide](https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw)
