Tunneling is a method used by attackers to exfiltrate data from one system to another. Different protocols are used for tunneling, often exploiting proxies or trusted protocols allowed by network controls.

---

## Basics of Tunneling

When attackers need to send data to an external host, they may employ tunneling, often establishing command and control over a compromised machine. Tunneling can occur over protocols like SSH, HTTP, HTTPS, DNS, and ICMP, each enabling attackers to bypass network security measures.

---

## ICMP Tunneling

In ICMP tunneling, attackers embed data into the data field of ICMP requests to conceal it within normal network traffic.

### Detecting ICMP Tunneling

Since ICMP tunneling involves placing data in the ICMP data field, it can be detected by examining data sizes in ICMP requests and replies.

1. **ICMP Filter**: Use the ICMP filter in Wireshark to view ICMP-specific traffic.

2. **Detecting Large Data Transfers**: Fragmented ICMP traffic or unusually large data fields (e.g., over 48 bytes) may indicate tunneling. Normal ICMP requests have smaller data fields, typically around 48 bytes, whereas tunneling traffic can show lengths up to 38,000 bytes.

3. **Inspecting Data Contents**: In Wireshark, examine the data field in ICMP requests for sensitive information (e.g., usernames and passwords). This is a direct sign of ICMP tunneling.

4. **Encoded Data**: Advanced attackers may encode or encrypt exfiltrated data within ICMP packets. Detecting encoded data might require manual decoding, as shown:
   ```bash
   echo 'VGhpcyBpcyBhIHNlY3VyZSBrZXk6IEtleTEyMzQ1Njc4OQo=' | base64 -d
   ```

If ICMP data lengths exceed typical sizes (e.g., 48 bytes), further analysis is warranted.

---

## Preventing ICMP Tunneling

- **Block ICMP Requests**: Disabling ICMP can prevent tunneling, though it may affect legitimate network diagnostics.
- **Inspect ICMP Requests and Replies**: By monitoring and analyzing ICMP traffic, especially data fields, suspicious tunneling activity can be detected and mitigated.