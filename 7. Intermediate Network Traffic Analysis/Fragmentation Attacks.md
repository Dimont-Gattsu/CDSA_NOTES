When analyzing network traffic, the IP layer is crucial for understanding packet transfers between hosts. This layer, however, lacks mechanisms to detect lost or tampered packets—these issues are managed by the transport or application layers. Key fields in the IP header include:

- **Length**: The IP header length
- **Total Length**: Entire IP packet length, including data
- **Fragment Offset**: Set when packets are fragmented, guiding reassembly at the destination
- **Source and Destination IP Addresses**: Identifying origin and target hosts

---

## Commonly Abused Fields in Fragmentation

Attackers may manipulate these fields to evade network controls. Understanding the misuse of these fields can enhance detection during traffic analysis.

### Fragmentation Abuse Techniques

Legitimate hosts fragment packets to transfer large data sets, following a maximum transmission unit (MTU) standard. Attackers abuse fragmentation to:

1. **IPS/IDS Evasion**: If IDS doesn’t reassemble fragments, attackers can use fragmented scans (e.g., with `nmap`) to bypass detection.
2. **Firewall Evasion**: Fragmented packets can bypass firewall controls if not reassembled before delivery.
3. **Firewall/IPS/IDS Resource Exhaustion**: Small MTU sizes (e.g., 10, 15 bytes) strain resources, possibly bypassing reassembly due to resource limits.
4. **Denial of Service**: Old hosts can be overwhelmed by large fragmented packets, causing denial-of-service.

A correctly configured network mechanism should use **delayed reassembly**—waiting for all fragments to reassemble and then performing packet inspection.

---

## Detecting Fragment Offset Irregularities

To inspect fragmentation anomalies, open the capture file in Wireshark:

```bash
wireshark nmap_frag_fw_bypass.pcapng
```

### Indicators of Fragmented Scans

1. **ICMP Requests**: Nmap or similar scans often start with ICMP requests for host discovery.
   ```bash
   nmap <host ip>
   ```

2. **Fragmented Packets with Specified MTU**: Attackers set a specific MTU to fragment packets.
   ```bash
   nmap -f 10 <host ip>
   ```
   - Packets with repeated fragmentation from a host indicate a possible fragmentation attack.

3. **One Host, Multiple Ports Pattern**: Fragmented scans generate responses with **RST flags** for closed ports, indicating scans across many ports.

---

## Configuring Wireshark for Reassembly

If Wireshark isn’t reassembling packets automatically, adjust settings under **Preferences** for the IPv4 protocol to ensure packet reassembly, facilitating more accurate inspection.