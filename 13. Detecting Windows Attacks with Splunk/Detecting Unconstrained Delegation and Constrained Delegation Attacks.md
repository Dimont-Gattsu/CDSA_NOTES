## Unconstrained Delegation

Unconstrained Delegation allows a service to authenticate to other resources on behalf of any user, potentially exposing sensitive data if compromised. Attackers may exploit this to retrieve and reuse Ticket Granting Ticket (TGT) tickets from memory, enabling lateral movement within a network.

### Attack Steps

1. **Identify Target Systems**: The attacker identifies systems where Unconstrained Delegation is enabled.
2. **Gain Access**: The attacker gains access to a system with Unconstrained Delegation enabled.
3. **Extract TGT Tickets**: Tools like Mimikatz are used to extract TGTs from memory, enabling impersonation.

### Detection Opportunities

- **PowerShell Commands**: Monitoring PowerShell script block logging (Event ID 4104) can reveal commands related to Unconstrained Delegation discovery.
- **LDAP Requests**: Log analysis can detect LDAP requests that search for delegation settings.
- **TGT Reuse**: Pass-the-Ticket detections may indicate TGTs being reused.

---

### Example Splunk Query: Detecting Unconstrained Delegation Attacks

**Description**: This search identifies PowerShell commands associated with Unconstrained Delegation discovery.

**Timeframe**: `earliest=1690544538 latest=1690544540`

```spl
index=main earliest=1690544538 latest=1690544540 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*" 
| table _time, ComputerName, EventCode, Message
```

---

## Constrained Delegation

Constrained Delegation restricts delegation permissions to specific services, allowing a service to act on behalf of a user only for designated resources. This is more restrictive than Unconstrained Delegation, yet attackers can still exploit it by using Service For User (S4U) extensions to impersonate users.

### Attack Steps

1. **Identify Constrained Delegation Accounts**: Attackers locate accounts with `msDS-AllowedToDelegateTo` properties.
2. **Extract TGT**: The attacker gains access to the TGT of a principal (user or computer).
3. **Use S4U Technique**: Using S4U2self and S4U2proxy, the attacker impersonates high-privileged accounts to access services.
4. **Access Services as Target User**: The attacker injects the ticket and accesses resources with the targeted privileges.

### Detection Opportunities

- **LDAP Queries and PowerShell Commands**: Monitoring for LDAP requests and PowerShell commands that query `msDS-AllowedToDelegateTo`.
- **Kerberos Authentication Traffic**: Monitoring unusual process connections to Domain Controllers on TCP/UDP port 88 (Kerberos) may indicate S4U activity.

---

### Example Splunk Query: Detecting Constrained Delegation Discovery with PowerShell Logs

**Description**: This search detects PowerShell commands attempting to discover `msDS-AllowedToDelegateTo` properties for Constrained Delegation accounts.

**Timeframe**: `earliest=1690544553 latest=1690562556`

```spl
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*" 
| table _time, ComputerName, EventCode, Message
```

---

### Example Splunk Query: Detecting Constrained Delegation with Sysmon Logs

**Description**: This query identifies processes making unusual network connections to the Domain Controller’s Kerberos port, potentially indicative of Constrained Delegation attacks using S4U.

**Timeframe**: `earliest=1690562367 latest=1690562556`

```spl
index=main earliest=1690562367 latest=1690562556 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

---

## Summary

Both Unconstrained and Constrained Delegation enable privilege escalation and lateral movement if improperly configured. Monitoring PowerShell commands, LDAP queries, and unusual Kerberos traffic with Splunk provides security teams with enhanced visibility into potential delegation attacks, allowing for proactive threat detection and mitigation.