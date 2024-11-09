Time-to-Live (TTL) attacks are used by attackers as an evasion technique. By setting a low TTL, attackers aim to bypass firewall, IDS, and IPS detection. This process works as follows:

---

## TTL Manipulation

1. **Crafting Low TTL Packets**: Attackers set a low TTL (e.g., 1, 2, 3).
2. **TTL Decrement**: As packets traverse each hop, the TTL decreases by one.
3. **Packet Discard**: When TTL reaches zero, the packet is discarded, ideally before reaching a firewall or filter.
4. **ICMP Response**: Expired packets trigger ICMP Time Exceeded messages from routers along the path, sent back to the source.

---

## Detecting IP TTL Irregularities

To detect TTL manipulation, capture and analyze traffic in Wireshark. While single instances are hard to spot, attackers often use TTL manipulation during port scans, generating noticeable patterns.

### Indicators in TTL Manipulation

1. **SYN, ACK from Service Ports**: A legitimate SYN, ACK response from a host’s service port may indicate a bypassed firewall.
2. **Low TTL Values**: Opening the IPv4 tab in Wireshark for suspicious packets may reveal unusually low TTL values.

### Mitigation Strategy

Implement a control that filters or discards packets with TTLs below a threshold. This helps prevent IP packet crafting attacks that exploit TTL manipulation.
