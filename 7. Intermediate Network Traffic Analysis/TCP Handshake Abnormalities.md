When attackers probe TCP services, certain behaviors might deviate from normal traffic patterns. To understand these anomalies, let's first review the standard TCP 3-way handshake.

---

## TCP Handshake

1. **SYN Request**: The client sends a TCP SYN request to initiate a connection.
2. **SYN-ACK Response**: If the port is open, the server responds with a SYN-ACK, indicating an open connection.
3. **Flags**: Various TCP flags signal specific actions or statuses during a connection.

| Flag | Description |
|------|-------------|
| URG  | Urgent data stream |
| ACK  | Acknowledges data receipt |
| PSH  | Pushes data to application layer immediately |
| RST  | Terminates the connection |
| SYN  | Initiates a TCP connection |
| FIN  | Ends a TCP connection |
| ECN  | Notifies congestion |

---

## Indicators of Abnormal TCP Handshake Patterns

- **Excessive Flags**: Multiple flags or repeated flags can indicate scanning.
- **Unusual Flags**: Irregular flag combinations may signal TCP RST attacks, hijacking attempts, or evasion tactics.
- **Single Host Targeting Multiple Ports or Hosts**: Scans often originate from one host targeting multiple ports or hosts. Decoy scans and random source attacks are also possible.

---

## Types of TCP Scans

### Excessive SYN Flags

One common scan type is SYN scanning, where attackers send SYN packets to target ports. Responses:

- **SYN Scan**: The attacker preemptively ends the handshake with an RST flag.
- **SYN Stealth Scan**: The attacker only partially completes the handshake to evade detection.

---

### No Flags (NULL Scan)

NULL scans use TCP packets with no flags, producing the following responses:

- **Open Port**: No response from the system.
- **Closed Port**: The system replies with an RST packet.

---

### Excessive ACK Flags

ACK scans use repeated ACK flags. Responses:

- **Open Port**: No response or an RST packet.
- **Closed Port**: Responds with an RST packet.

---

### Excessive FIN Flags

In FIN scans, all packets are marked with the FIN flag. Responses:

- **Open Port**: No response from the system.
- **Closed Port**: The system replies with an RST packet.

---

### Xmas Tree Scan (All Flags Set)

Xmas tree scans involve setting all TCP flags. Responses:

- **Open Port**: Either no response or an RST packet.
- **Closed Port**: Responds with an RST packet.

Xmas tree scans are distinct and straightforward to identify due to the presence of all flags.
