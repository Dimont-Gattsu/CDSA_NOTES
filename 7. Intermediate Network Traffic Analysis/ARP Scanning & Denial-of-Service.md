We might discern additional aberrant behaviors within the ARP requests and replies. Poisoning and spoofing are central to ARP-based denial-of-service (DoS) and man-in-the-middle (MITM) attacks, but adversaries could also leverage ARP for information gathering. Thankfully, we possess the skills to detect and evaluate these tactics following similar procedures.

---

## ARP Scanning Signs

Typical red flags indicating ARP scanning include:
- Broadcast ARP requests sent to sequential IP addresses (.1, .2, .3, ...)
- Broadcast ARP requests sent to non-existent hosts
- Unusual volume of ARP traffic from a potentially malicious or compromised host

### Finding ARP Scanning

By opening `ARP_Scan.pcapng` in Wireshark and applying the filter `arp.opcode`, we might observe:

- **ARP Scanning**: ARP requests propagated by a single host to all IPs sequentially, symptomatic of ARP scanning (common in scanners like Nmap).
- **Active Hosts Respond**: Detected ARP replies from live hosts indicate successful information gathering by the attacker.

---

## Identifying Denial-of-Service

Attackers may:
1. Use ARP scanning to identify live hosts.
2. Transition to a DoS attack, contaminating the subnet by manipulating as many ARP caches as possible, or establishing a MITM position.

### ARP DoS Tactics

- **Corrupt Router's ARP Cache**: Attack traffic focuses on declaring new physical addresses for all live IPs.
- **Duplicate IP Allocations**: The attacker assigns 192.168.10.1 to multiple clients, aiming to disrupt communication by corrupting ARP caches and obstructing traffic.

---

## Responding to ARP Attacks

Upon identifying ARP anomalies, the following steps can be taken:

- **Tracing and Identification**: Locating the physical machine behind the attack can halt its activities. In some cases, the attacking machine may itself be compromised.
- **Containment**: Disconnect or isolate the affected area at the switch or router level to stop further data exfiltration, effectively terminating DoS or MITM attacks.

> **Note:** Link layer attacks may initially seem minor but detecting them can prevent data exfiltration from higher OSI layers.
