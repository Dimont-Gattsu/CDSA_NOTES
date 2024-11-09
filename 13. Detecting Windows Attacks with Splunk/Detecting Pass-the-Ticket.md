## Overview of Pass-the-Ticket

**Pass-the-Ticket (PtT)** is a technique allowing attackers to move laterally within a network by using Kerberos tickets instead of passwords. With administrative access, an attacker can extract valid Kerberos tickets (TGT or TGS) from a system's memory and use them to access resources without needing the user’s password.

### Pass-the-Ticket Attack Steps:
1. **Extract Kerberos Tickets**: The attacker uses tools like Mimikatz to extract TGT or TGS tickets from a compromised system.
2. **Authenticate with Extracted Ticket**: The attacker submits the ticket in the current logon session, authenticating as the user without needing the password.
3. **Lateral Movement**: Using the ticket, the attacker can access additional systems or resources across the network.

### Kerberos Authentication Process & Related Windows Security Events
- **Event ID 4624**: Successful logon to the system.
- **Event ID 4648**: Explicit credential logon attempt.
- **Event ID 4672**: Special logon indicating administrative privileges.
- **Event ID 4768**: TGT request in the Kerberos process.
- **Event ID 4769**: TGS request in the Kerberos process.
- **Event ID 4770**: TGS ticket renewal.

## Pass-the-Ticket Detection Opportunities

### Key Detection Logic
Detecting PtT attacks requires monitoring for Kerberos service tickets issued without a preceding TGT request. Attackers may import a TGT directly into a session, creating a gap where a TGS request (Event ID 4769) or ticket renewal (Event ID 4770) lacks an associated TGT request (Event ID 4768). Monitoring for discrepancies in the authentication process can reveal PtT attempts.

---

### Example 1: Detection of Kerberos TGS Requests without Prior TGT Requests

**Description**: This search looks for Kerberos service ticket requests (4769) and renewals (4770) without a prior TGT request (4768) from the same system, potentially indicating an imported TGT.

**Timeframe**: `earliest=1690392405 latest=1690451745`

```spl
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

### Explanation of Key Components

1. **Event Filtering**:
   - Filters events to include only Kerberos-related Event IDs 4768, 4769, and 4770 from the Security log, excluding machine accounts (`user!=*$`).

2. **Regular Expressions**:
   - **Username Extraction**: Extracts the username from the user field for easier identification.
   - **IP Extraction**: Extracts IPv4 addresses from `src_ip`, handling IPv4-mapped IPv6 addresses by focusing on the IPv4 portion.

3. **Transaction Command**:
   - **Purpose**: Groups related events into transactions by `username` and `src_ip_4` fields, beginning with EventCode 4768 (TGT request).
   - **Parameters**: `maxspan=10h` sets a 10-hour max transaction window, allowing for long-duration logon sessions; `keepevicted=true` ensures open transactions remain visible.

4. **Filter for Open Transactions**:
   - **closed_txn=0**: Filters for transactions lacking an end event, showing cases where TGS or renewal tickets were requested without a preceding TGT.

5. **Display Results**:
   - Shows relevant fields like `_time`, `ComputerName`, `username`, `src_ip_4`, `service_name`, and `category` to facilitate analysis.

---

### Example 2: Detection of TGS Requests and Anomalous Behavior

In cases where attackers import TGS tickets without a valid TGT request, anomalies can appear in Event ID 4771 (Pre-Authentication Failed). By monitoring mismatches in failure codes and authentication types, additional PtT attacks may be detected.