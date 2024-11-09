TCP inherently lacks protection mechanisms to prevent attackers from terminating or hijacking connections. This vulnerability can manifest as connection termination via RST packets or through more advanced connection hijacking techniques.

---

## TCP Connection Termination

In a TCP RST packet injection attack (also known as TCP connection termination), an attacker aims to disrupt network service. This attack involves:

1. **Source Spoofing**: The attacker spoofs the source address to match that of the target machine.
2. **RST Flag Injection**: The TCP packet is crafted with the RST flag to terminate the connection.
3. **Targeted Destination Port**: The attacker specifies a destination port in active use by the target machine.

### Detecting TCP RST Attacks

- **High Packet Volume**: An unusual number of packets directed at a single port may indicate an RST attack.
- **MAC Address Discrepancy**: If packets with a spoofed IP (e.g., 192.168.10.4) show an unexpected MAC address not matching the registered one (e.g., `aa:aa:aa:aa:aa:aa`), this suggests malicious activity.
  
While MAC spoofing is possible, retransmissions or other inconsistencies may also arise, as seen in ARP poisoning scenarios.

---

## TCP Connection Hijacking

In more sophisticated attacks, TCP connection hijacking allows attackers to monitor and control an active session. This attack involves:

1. **Sequence Number Prediction**: The attacker predicts sequence numbers to inject packets into the correct position within the target connection.
2. **Source Spoofing**: Similar to RST attacks, the attacker spoofs the source IP to impersonate the target machine.
3. **Blocking ACKs**: To maintain the hijacked connection, the attacker blocks or delays ACK packets from reaching the target. This is commonly done via ARP poisoning.

### Indicators of TCP Hijacking

- **Sequence Anomalies**: Inconsistent or unusual sequence numbers may indicate sequence prediction attempts.
- **Blocked or Delayed ACKs**: ACK delays or absences can hint at attempts to hijack the session.
  
TCP connection hijacking often pairs with ARP poisoning, which may produce observable traffic anomalies.
