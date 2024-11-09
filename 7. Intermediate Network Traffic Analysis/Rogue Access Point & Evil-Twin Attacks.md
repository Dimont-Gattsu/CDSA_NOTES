## Rogue Access Point (AP)

A rogue AP is an unauthorized device connected directly to the network, potentially bypassing perimeter controls. These APs may:
- Circumvent network segmentation
- Provide unauthorized access to restricted sections of a network
- Occasionally, infiltrate air-gapped networks

---

## Evil-Twin

An evil-twin AP is usually a standalone access point, separate from the network, often used by attackers to intercept data via man-in-the-middle (MITM) attacks. Such APs:
- Are commonly set up to capture wireless credentials and other sensitive information
- Might host hostile portals to lure users into disclosing credentials

---

## Detection with Airodump-ng

We can utilize `airodump-ng` with an ESSID filter to detect Evil-Twin APs:
```bash
sudo airodump-ng -c 4 --essid HTB-Wireless wlan0 -w raw
```

Example output:
```
CH  4 ][ Elapsed: 1 min ][ 2023-07-13 16:06    
BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
F8:14:FE:4D:E6:F2   -7 100      470      155    0   4   54   OPN              HTB-Wireless
F8:14:FE:4D:E6:F1   -5  96      682        0    0   4  324   WPA2 CCMP   PSK  HTB-Wireless 
```

The example shows an attacker-created open AP with an identical ESSID to our legitimate AP, suggesting a hostile portal attack. 

---

## Beacon Analysis for Evil-Twin Detection

To confirm anomalies, examine beacon frames with this Wireshark filter:
```plaintext
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```

**Beacon Analysis**:
- **RSN Information**: The legitimate AP’s RSN info may indicate WPA2 with AES/TKIP and PSK. In contrast, a malicious AP might lack RSN information.
- **Additional Fields**: For sophisticated attacks, check vendor-specific info and other unique identifiers that might be missing in the attacker’s AP.

---

## Identifying Compromised Users

In cases of open-network evil-twin attacks:
- Use the following Wireshark filter to isolate traffic for the suspicious AP:
  ```plaintext
  (wlan.bssid == F8:14:FE:4D:E6:F2)
  ```

Detecting ARP requests from a client device on this network could indicate a potential compromise. Record:
- Client device’s MAC address
- Host name

Take responsive actions like password resets to mitigate risk.

---

## Detecting Rogue Access Points

Rogue AP detection often involves network device monitoring. Look for:
- Unrecognized networks with strong signals, especially open networks
- Potential hotspots in close proximity (e.g., Windows hotspots)

Unfamiliar networks without encryption may indicate rogue access points set up to bypass network security.