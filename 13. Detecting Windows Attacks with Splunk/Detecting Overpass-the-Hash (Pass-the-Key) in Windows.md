## Overview of Overpass-the-Hash

**Overpass-the-Hash (Pass-the-Key)** allows attackers to authenticate via Kerberos using stolen password hashes, enabling them to request Kerberos TGTs and gain unauthorized access across systems without using NTLM.

### Attack Steps
1. **Extract User Hashes**: The attacker uses tools like Mimikatz to obtain the NTLM hash of a logged-in user, requiring local administrator privileges.
2. **Request TGT with Rubeus**: Using Rubeus, the attacker crafts a raw AS-REQ request for a TGT for a specified user. This step does not require elevated privileges, making it a more covert approach.
3. **Submit Ticket**: The attacker injects the requested TGT into the current session, similar to Pass-the-Ticket attacks, for further lateral movement.

## Overpass-the-Hash Detection Opportunities

### Key Detection Logic
- **Mimikatz Detection**: Artifacts from Mimikatz-based Overpass-the-Hash attacks resemble those of Pass-the-Hash and can be detected using similar techniques.
- **Rubeus Detection**: When Rubeus sends an AS-REQ request directly to the Domain Controller on TCP/UDP port 88, it generates Event ID 4768. However, unusual processes communicating over port 88 to the DC, other than lsass.exe, can help identify potential Overpass-the-Hash activity.

---

## Example Splunk Query: Detecting Overpass-the-Hash Targeting Rubeus

**Description**: This query identifies AS-REQ requests on port 88 from unusual processes, specifically looking for Event ID 3 with a destination port of 88 and excluding `lsass.exe`. 

**Timeframe**: `earliest=1690443407 latest=1690443544`

```spl
index=main earliest=1690443407 latest=1690443544 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

### Explanation of Key Components

1. **Event Filtering**:
   - **Source Selection**: Filters events from Sysmon’s Operational log (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`).
   - **EventCode 3**: Captures network connections made from the host, specifically targeting traffic to `dest_port=88` (Kerberos), and excludes `Image=lsass.exe` as it is a legitimate process accessing Kerberos services.
   - **OR EventCode 1**: Captures all process creation events for correlation.

2. **Event Statistics**:
   - **EventStats**: Adds the list of processes for each process ID, stored as `process`.
   - **Where EventCode=3**: Filters for network connection events on port 88.

3. **Aggregation and Filtering**:
   - **Stats Count by Fields**: Groups events based on `_time`, `Computer`, `dest_ip`, `dest_port`, `Image`, and `process`, aggregating with `count`.
   - **Fields - count**: Removes the count field from the final output for clarity.

---

### Additional Recommendations

- **Monitor Port 88 Traffic**: Create alerts for network activity to port 88 from unexpected processes. 
- **Correlate Events**: Cross-reference Event ID 4768 (Kerberos TGT Request) with suspicious processes in Sysmon logs, focusing on tools like Rubeus.
- **Behavior Analysis**: Contextualize detections with user and system behaviors, flagging unusual patterns like rapid logon attempts, lateral movement, or access to high-value assets.

---

This approach enables early detection of Overpass-the-Hash attacks, specifically targeting scenarios where attackers leverage Rubeus to request TGTs via AS-REQ requests over Kerberos, aiding in identifying stealthy lateral movement attempts.