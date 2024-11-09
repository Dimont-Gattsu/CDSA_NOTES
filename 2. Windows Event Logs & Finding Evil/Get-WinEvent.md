Understanding the importance of mass analysis of Windows Event Logs and Sysmon logs is pivotal in the realm of cybersecurity, especially in Incident Response (IR) and threat hunting scenarios. These logs hold invaluable information about the state of your systems, user activities, potential threats, system changes, and troubleshooting information.

## Using Get-WinEvent

The `Get-WinEvent` cmdlet is a powerful tool in PowerShell for querying Windows Event logs en masse. It allows the retrieval of different types of event logs, including classic logs (like System and Application logs) and Event Tracing for Windows (ETW) logs.

### Listing Available Logs

To retrieve a list of all logs and display key properties:

```powershell
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize
```

#### Output Example
| LogName                                     | RecordCount | IsClassicLog | IsEnabled | LogMode | LogType         |
|---------------------------------------------|-------------|--------------|-----------|---------|-----------------|
| Windows PowerShell                          | 2916        | True         | True      | Circular| Administrative  |
| System                                      | 1786        | True         | True      | Circular| Administrative  |

### Listing Event Providers

Event providers are sources of events in the logs. To list providers and their associated logs:

```powershell
Get-WinEvent -ListProvider * | Format-Table -AutoSize
```

### Retrieving Specific Events

#### System Log Events

Retrieve the first 50 events from the System log:

```powershell
Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

#### WinRM Operational Log

Retrieve events from `Microsoft-Windows-WinRM/Operational`:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering by Date Range

To filter events by date, specify a range:

```powershell
$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
$endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering by Event ID and Properties

Retrieve Sysmon event IDs 1 and 3:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
```

### Filtering with XML Content

Detect specific DLL loads (`mscoree.dll` and `clr.dll`) using XML:

```powershell
$Query = @"
<QueryList>
    <Query Id="0">
        <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]</Select>
    </Query>
</QueryList>
"@
Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}
```

### Detecting Specific Network Connections

An example command to check for network connections to a specific IP:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"
```

### Viewing All Properties of a Sysmon Event

To get a detailed view of all properties in a Sysmon event:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *
```

### Searching for Encoded Commands

Detects events where encoded commands (`-enc`) are used, often for obfuscating scripts:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List
```

These examples demonstrate using `Get-WinEvent` for efficient log analysis, including filtering, XML queries, and detailed event inspection.
