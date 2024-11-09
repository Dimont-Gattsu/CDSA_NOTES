#### Overview
- The Address Resolution Protocol (ARP) is frequently targeted for attacks like MITM and DoS.
- ARP attacks often use broadcast communication, aiding in detectability via packet sniffing.

### How Address Resolution Protocol Works

1. **ARP Basics:** Hosts need the MAC address to send data, obtained through ARP requests.
2. **Process Steps:**
   - Host A checks ARP cache or broadcasts an ARP request if the IP isn’t found.
   - Host B replies with its IP-MAC mapping, updating Host A’s ARP cache.

### ARP Poisoning & Spoofing

- **ARP Cache Poisoning:** Attackers send false ARP messages to corrupt caches, redirecting traffic.
  - **Attack Steps:**
    - Attacker sends forged ARP messages to the victim and router, altering their ARP tables.
    - If the attacker forwards traffic, they intercept and modify data, enabling MITM attacks.

#### Detection & Prevention

- **Detection Techniques:**
  - Monitor for unusual ARP traffic patterns (e.g., repetitive ARP requests).
  - Track IP-MAC inconsistencies to spot potential spoofing.

- **Prevention Controls:**
  - **Static ARP Entries**: Prevents ARP cache poisoning, though it increases maintenance.
  - **Port Security on Switches/Routers**: Blocks unauthorized devices attempting spoofing.

### Practical Detection Steps Using tcpdump and Wireshark

1. **Install tcpdump** (if not present):
   ```bash
   sudo apt install tcpdump -y
   ```

2. **Capture ARP Traffic**:
   ```bash
   sudo tcpdump -i eth0 -w filename.pcapng
   ```

3. **Analyze with Wireshark**:
   ```bash
   wireshark ARP_Spoof.pcapng
   ```
   - **Wireshark Filters**:
     - Filter ARP Requests: `arp.opcode == 1`
     - Filter ARP Replies: `arp.opcode == 2`
     - Detect Duplicates: `arp.duplicate-address-detected && arp.opcode == 2`

4. **Examine IP-MAC Anomalies**:
   - Use `arp -a` on Linux to check IP-MAC mappings:
     ```bash
     arp -a | grep 50:eb:f6:ec:0e:7f
     arp -a | grep 08:00:27:53:0c:ba
     ```

5. **Filter in Wireshark**:
   - Track suspicious MAC interactions:
     ```plaintext
     eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba
     ```

