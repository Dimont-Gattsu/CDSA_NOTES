While analyzing network traffic, Telnet and UDP traffic can sometimes reveal suspicious or anomalous activities that might otherwise be overlooked.

---

## Telnet

Telnet, a protocol for bidirectional interactive communication, is generally outdated due to security concerns and is commonly replaced by SSH. However, legacy systems (e.g., older Windows NT machines) may still rely on Telnet for remote command control, making it worth monitoring for any unusual connections.

### Detecting Traditional Telnet Traffic on Port 23

When observing traffic on **Port 23** (Telnet’s default port) in Wireshark, examine communications closely for signs of misuse. Although Telnet traffic is unencrypted and straightforward to inspect, attackers may encrypt or obfuscate data in Telnet traffic, making it necessary to approach with caution.

### Unrecognized Telnet Traffic on Non-Standard Ports

Telnet can operate on any port, and attackers may shift Telnet communications to non-standard ports. For example, communications on **Port 9999** might indicate an attempt to obscure malicious activity. In this case, follow the TCP stream to investigate further.

### Telnet Protocol through IPv6

If IPv6 Telnet traffic is detected in an IPv4-configured network, this could indicate unauthorized access. To filter IPv6 Telnet traffic in Wireshark, use:
```plaintext
((ipv6.src_host == fe80::c9c8:ed3:1b10:f10b) or (ipv6.dst_host == fe80::c9c8:ed3:1b10:f10b)) and telnet
```

This filter helps isolate Telnet traffic on specific IPv6 addresses for in-depth inspection.

---

## Monitoring UDP Communications

Attackers may use **UDP** to bypass typical TCP-based monitoring, as UDP’s connectionless, fast-transmission nature can be advantageous for covert data exfiltration.

### TCP vs. UDP

UDP, unlike TCP, is connectionless, meaning no SYN, SYN/ACK, ACK handshake is required before transmission. This difference allows for faster communication, but also reduces reliability and accountability in tracking connections.

### Common Uses of UDP

While investigating UDP traffic, consider these legitimate use cases:
1. **Real-time Applications**: Streaming media, gaming, and real-time voice/video rely on UDP for faster connections.
2. **DNS (Domain Name System)**: DNS queries and responses primarily use UDP.
3. **DHCP (Dynamic Host Configuration Protocol)**: UDP is used for assigning IP addresses and network configurations.
4. **SNMP (Simple Network Management Protocol)**: UDP supports network monitoring and management.
5. **TFTP (Trivial File Transfer Protocol)**: TFTP, used for basic file transfers, particularly in older systems, also uses UDP.

For unusual UDP traffic, follow the stream in Wireshark to inspect its contents and verify legitimacy.