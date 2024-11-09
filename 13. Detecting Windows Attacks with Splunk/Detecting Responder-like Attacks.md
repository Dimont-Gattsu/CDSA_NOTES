## Overview of LLMNR/NBT-NS/mDNS Poisoning

**LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS (NetBIOS Name Service)**, along with **mDNS (Multicast DNS)**, are name resolution protocols. These protocols assist in resolving local hostnames to IP addresses when DNS fails. However, these protocols lack security mechanisms, making them susceptible to **spoofing** and **poisoning attacks**.

### Attack Flow:
1. A victim device sends a name resolution query due to a mistyped or unresolved hostname.
2. DNS fails to resolve this query.
3. The device uses LLMNR, NBT-NS, or mDNS to try resolving the hostname.
4. An attacker using a tool like **Responder** responds to the query, posing as the requested host, thus poisoning the name resolution.

**Result**: The attacker gains the victim’s **NetNTLM hash**, which can potentially be cracked or used to gain access to other systems.

---

## Detection Opportunities for Responder Attacks

Detection is challenging, but organizations can:
1. Monitor for unusual patterns in **LLMNR and NBT-NS traffic**, especially increased name resolution requests.
2. Use **honeypot-like techniques** to detect unexpected successful resolutions for non-existent hosts.
3. Automate PowerShell-based detection scripts to log suspicious activity, such as unexpected LLMNR or NBT-NS responses.

### PowerShell Logging Example:
```powershell
# Setup Event Log for LLMNR detection
New-EventLog -LogName Application -Source LLMNRDetection

# Log an Event
Write-EventLog -LogName Application -Source LLMNRDetection -EventId 19001 -Message $msg -EntryType Warning
```

---

## Detecting Responder-like Attacks with Splunk

### Timeframe:
- **Earliest**: `1690290078`
- **Latest**: `1690291207`

### Splunk Queries

#### 1. Detecting LLMNR Detection Alerts

```spl
index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

This query searches the `LLMNRDetection` logs created by the PowerShell script and outputs the log time, computer name, source name, and message details.

#### 2. Sysmon Event ID 22 for DNS Query Tracking

Sysmon Event ID 22 monitors DNS queries. By tracking queries for mistyped file shares, it’s possible to detect suspicious activity.

```spl
index=main earliest=1690290078 latest=1690291207 EventCode=22 
| table _time, Computer, user, Image, QueryName, QueryResults
```

**Explanation**:
- This query retrieves DNS query events, showing the computer, user, process image, queried hostname (`QueryName`), and results (`QueryResults`).

#### 3. Event ID 4648 - Explicit Logons to Rogue File Shares

Event ID 4648 can help detect explicit logon attempts to attacker-controlled file shares, providing insight into credential theft attempts.

```spl
index=main earliest=1690290814 latest=1690291207 EventCode IN (4648) 
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

**Explanation**:
- This query finds explicit logon attempts, listing details like user and target server. Sorting by `_time` orders the events chronologically.