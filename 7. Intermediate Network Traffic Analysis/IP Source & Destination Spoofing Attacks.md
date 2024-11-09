There are cases where irregular IPv4 and IPv6 traffic might arise from manipulation of source and destination IP fields. Key points to consider in traffic analysis include:

- **Source IP for Incoming Traffic**: Should always be from within our subnet. An external source IP suggests possible packet crafting.
- **Source IP for Outgoing Traffic**: Should also be within our subnet. An unusual IP range may indicate malicious traffic from within the network.

---

## Attack Methods Involving IP Spoofing

Attackers may craft source and destination IP fields for various purposes:

1. **Decoy Scanning**: Changes source IP to bypass firewall restrictions, posing as a host in the target’s subnet to evade detection.
2. **Random Source Attack (DDoS)**: Sends high volumes of traffic from randomized source IPs to exhaust resources on the destination host.
3. **LAND Attacks**: Spoofs the source IP to match the destination, causing resource exhaustion or crashes on the target host.
4. **SMURF Attacks**: Sends ICMP packets to multiple hosts with the victim's IP as the source, flooding the victim with replies.
5. **Initialization Vector Generation**: In older WEP networks, repeated packet injection with crafted IPs can build decryption tables for statistical attacks.

These attacks typically derive from IP layer manipulation, rather than ARP poisoning, though both methods are often combined.

---

## Detecting Decoy Scanning Attempts

An attacker may alter their source IP to mimic a legitimate host, aiming to bypass IDS/Firewall controls. Indicators of decoy scanning include:

- **Initial Fragmentation** from a spoofed address
- **TCP Traffic** from the legitimate source address with RST flags for closed ports

Detection techniques:
- **Packet Reassembly**: Ensure IDS/IPS/Firewall systems can reconstruct packets, mimicking destination host behavior.
- **Connection Consistency**: Watch for connections initiated by one host and completed by another, indicating address cloaking.

---

## Detecting Random Source Attacks

Random source attacks can target a specific service by flooding it with traffic from varied source addresses. Indicators include:

- **Single Port Utilization**: Traffic from multiple random hosts targeting a single port.
- **Incremental Base Port**: Consistent base ports with minimal randomization.
- **Identical Length Fields**: In contrast to legitimate user traffic, crafted packets may have uniform lengths.

---

## Detecting SMURF Attacks

SMURF attacks leverage ICMP packets with the victim’s IP as the source, prompting responses that overwhelm the victim. Attack steps:

1. **ICMP Request** to live hosts with the victim’s IP as the source.
2. **ICMP Reply** from live hosts to the victim, exhausting its resources.

**Detection**: Excessive ICMP replies to a single host. Attackers may add fragmentation or extra data to amplify the attack volume.

---

## Detecting LAND Attacks

LAND attacks spoof the source IP to match the destination IP, using high traffic volume and port re-use to disrupt service. This congestion makes genuine connections difficult to establish with the targeted host.
