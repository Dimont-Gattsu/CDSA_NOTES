## Golden Ticket

**Golden Ticket** attacks involve forging a Ticket Granting Ticket (TGT) to impersonate a domain administrator and gain full access to the domain. This attack is persistent and difficult to detect as it uses a valid, forged TGT that can be created offline by an attacker.

### Attack Steps

1. **Extract KRBTGT Hash**: The attacker obtains the NTLM hash of the KRBTGT account, typically using DCSync or by dumping NTDS.dit and LSASS.
2. **Forge TGT**: The attacker creates a TGT using the KRBTGT hash, granting themselves domain administrator privileges.
3. **Inject Forged TGT**: The attacker injects this TGT into a logon session, enabling unauthorized access to domain resources.

### Detection Opportunities

Detection relies on identifying indicators such as:
- **DCSync activity**: Monitoring for suspicious DCSync requests.
- **NTDS.dit or LSASS access**: Sysmon Event ID 10 can help track LSASS access for hash extraction.
- **Pass-the-Ticket alerts**: Golden Ticket use resembles Pass-the-Ticket behaviors.

---

## Example Splunk Query: Detecting Golden Tickets

**Description**: This search identifies Golden Ticket use by looking for Kerberos events without an associated Event ID 4768. These unlinked tickets may indicate forgery.

**Timeframe**: `earliest=1690451977 latest=1690452262`

```spl
index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

---

## Silver Ticket

**Silver Ticket** attacks allow adversaries to create forged service-specific TGS tickets for targeted resources, providing limited access compared to Golden Tickets.

### Attack Steps

1. **Extract Service Account Hash**: The attacker extracts the NTLM hash of a target service account (e.g., SQL Server).
2. **Forge TGS Ticket**: Using the hash, the attacker creates a forged TGS ticket.
3. **Inject and Access**: The attacker injects the forged ticket into a session to gain access to specific resources.

### Detection Opportunities

Detection focuses on:
- **New User Creation**: Event ID 4720 can identify newly created accounts.
- **Privilege Assignments**: Event ID 4672 helps monitor special logon privileges given to accounts, which may indicate suspicious access.

---

## Example Splunk Queries for Silver Ticket Detection

### Query 1: Comparing Created Users with Logged-in Users

**Description**: This search cross-references newly created users against recent logins to detect suspicious account activity.

**User List Creation**:

```spl
index=main latest=1690448444 EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

**Logged-in Users Comparison**:

**Timeframe**: `latest=1690545656`

```spl
index=main latest=1690545656 EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| eval last24h = 1690451977
| where firstTime > last24h
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```

### Query 2: Detecting Special Privileges on New Logon Events

**Description**: This search identifies accounts with special privileges assigned recently, indicating potentially unauthorized access using Silver Tickets.

**Timeframe**: `latest=1690545656`

```spl
index=main latest=1690545656 EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h = 1690451977
| where firstTime > last24h
| table firstTime, ComputerName, Account_Name
| convert ctime(firstTime)
```

---

## Summary

Golden Ticket and Silver Ticket attacks exploit the Kerberos authentication process to allow unauthorized access within a Windows Active Directory environment. Detection efforts focus on identifying anomalies in user logons, newly created accounts, and assigned privileges. By combining behavioral and event-based detections in Splunk, security teams can improve their ability to identify and respond to these advanced attacks.