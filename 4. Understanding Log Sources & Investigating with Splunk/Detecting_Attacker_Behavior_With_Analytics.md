In threat detection, anomaly-based detection models help identify unusual patterns by profiling typical behavior and flagging deviations. Splunk's analytics-based approach often uses statistical commands like `streamstats` to establish baselines, allowing us to detect unusual activity that may indicate an intrusion.

## Example 1: Detecting Anomalous Network Connections with `streamstats`

This example monitors network connections by process, alerting on processes that exceed the expected frequency of connections.

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | bin _time span=1h | stats count as NetworkConnections by _time, Image | streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image | eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1
```

### Explanation:
- `streamstats` calculates a rolling average and standard deviation of network connections over 24 hours.
- `isOutlier` flags processes whose network connections exceed 0.5 standard deviations above the average, signaling potential command-and-control activity.

## Example 2: Detecting Abnormally Long Commands

Attackers may use long command lines to evade detection. This query identifies unusually lengthy commands.

```spl
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

After examining the output, filtering out benign activity refines the results:

```spl
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe ParentImage!="*msiexec.exe" ParentImage!="*explorer.exe" | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

## Example 3: Detecting Unusual cmd.exe Activity by User

Monitoring `cmd.exe` use can help flag suspicious behavior:

```spl
index="main" EventCode=1 (CommandLine="*cmd.exe*") | bucket _time span=1h | stats count as cmdCount by _time User CommandLine | eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev | eval isOutlier=if(cmdCount > avg+1.5*stdev, 1, 0) | search isOutlier=1
```

## Example 4: Detecting Processes Loading Many DLLs Rapidly

Malware may load multiple DLLs quickly. This query identifies such behavior:

```spl
index="main" EventCode=7 NOT (Image="C:\Windows\System32*") NOT (Image="C:\Program Files*") | bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```

## Example 5: Detecting Multiple Instances of a Process on the Same Host

Repetitive process executions can indicate abnormal activity:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | stats count by Image, ParentImage
```

For deeper analysis, target specific pairs such as `rundll32.exe` and `svchost.exe`:

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | search Image="C:\Windows\System32\rundll32.exe" ParentImage="C:\Windows\System32\svchost.exe" | table CommandLine, ParentCommandLine
```

## Conclusion
Using analytics, we establish behavioral baselines and identify deviations to uncover suspicious activity. While this approach highlights anomalies, it works best in combination with TTP-based detection to cover a broader spectrum of potential threats.
