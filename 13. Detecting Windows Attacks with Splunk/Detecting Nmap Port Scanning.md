## Overview

Port scanning, especially with tools like Nmap, is a common technique used by attackers to identify open ports and services on a target system. In this context, we are looking to detect instances where a source IP is attempting to connect to multiple ports on a destination IP in a short time frame, indicative of scanning behavior. Using Splunk and Zeek logs, we can identify these patterns by filtering for zero payload traffic and counting unique port connections.

---

## Splunk Query for Detecting Nmap Scans

The following Splunk query identifies potential Nmap port scans by filtering for network connections with no payload (i.e., `orig_bytes=0`) and counting the number of distinct ports accessed within private IP ranges. By setting a threshold of three or more ports within a five-minute interval, we can flag this activity as suspicious.

### Query Breakdown

```spl
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8) 
| bin span=5m _time 
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip 
| where num_dest_port >= 3
```

### Detailed Steps:

1. **Select the Appropriate Data Source**:
   - `index="cobaltstrike_beacon"` specifies the index where the relevant Zeek connection logs are stored.
   - `sourcetype="bro:conn:json"` specifies the source type as Zeek JSON logs for connection data.

2. **Filter for Zero-Payload Connections**:
   - `orig_bytes=0` targets connection attempts where the initial payload size is zero. This typically indicates a scan attempt since no actual data is being transmitted, just the connection request.

3. **Restrict to Internal IP Ranges**:
   - `dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)` filters the results to only include private IP ranges. This approach is commonly used to monitor internal network traffic for signs of port scanning, which is a common reconnaissance activity within internal networks.

4. **Time-Binning Events**:
   - `| bin span=5m _time` groups the events into 5-minute intervals, helping us detect multiple scanning attempts within a brief period, which is characteristic of port scanning activity.

5. **Count Unique Ports Accessed**:
   - `| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip` counts the distinct destination ports (using `dc(dest_port)`) that each source IP (`src_ip`) connects to on each destination IP (`dest_ip`) within the 5-minute time window.

6. **Set a Threshold for Flagging Scans**:
   - `| where num_dest_port >= 3` filters to include only events where three or more unique ports were accessed by the same source IP within the defined 5-minute window. This threshold suggests potential scanning behavior as multiple ports are probed in a short time frame.

---

### Interpreting Results

- **Flagging Potential Scanners**: IPs that attempt to connect to three or more ports within a short window, without sending any payload data, are likely engaging in port scanning activity.
- **Adjusting Thresholds**: If there are many false positives, consider adjusting the `num_dest_port` threshold. Higher values indicate more aggressive scanning.