## Overview of Kerberoasting

**Kerberoasting** is an attack targeting service accounts in Active Directory. Attackers leverage weaknesses in Kerberos ticket encryption to extract and attempt to crack password hashes of service accounts.

### Kerberoasting Attack Steps:
1. **Identify Service Accounts**: The attacker enumerates AD to find accounts with Service Principal Names (SPNs) set.
2. **Request TGS Tickets**: They request TGS tickets for these accounts, which contain password hashes.
3. **Offline Brute-Force**: The encrypted hashes are then cracked offline using tools like Hashcat or John the Ripper.

### Detection Opportunities for Kerberoasting

Detecting Kerberoasting involves monitoring for unusual LDAP queries that seek SPNs, followed by detecting TGS requests without corresponding logons. Relevant Windows events include:
- **Event ID 4768**: Kerberos TGT Request
- **Event ID 4769**: Kerberos Service Ticket Request
- **Event ID 4648**: Logon attempts with explicit credentials.

---

## Detecting Kerberoasting With Splunk

### Example 1: Detecting Benign TGS Requests

**Timeframe**: `earliest=1690388417 latest=1690388630`

```spl
index=main earliest=1690388417 latest=1690388630 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc) 
| dedup RecordNumber 
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
```

### Example 2: Detecting Kerberoasting Through SPN Querying

**Timeframe**: `earliest=1690448444 latest=1690454437`

```spl
index=main earliest=1690448444 latest=1690454437 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

### Example 3: Detecting TGS Requests Without Logon Events

**Timeframe**: `earliest=1690450374 latest=1690450483`

```spl
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time 
| search username!=*$ 
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

---

## Detecting AS-REPRoasting

**AS-REPRoasting** targets accounts with pre-authentication disabled. Attackers can request an AS-REQ ticket, capturing the encrypted TGT without needing to authenticate, which they then attempt to crack.

### Detection Opportunities for AS-REPRoasting

Key detection opportunities include identifying accounts with **Pre-Authentication disabled** through LDAP monitoring and detecting **TGT requests for accounts without pre-authentication** (Event ID 4768 with `Pre_Authentication_Type=0`).

---

## Detecting AS-REPRoasting With Splunk

### Example 1: Querying Accounts With Pre-Auth Disabled

**Timeframe**: `earliest=1690392745 latest=1690393283`

```spl
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:SilkService-Log" 
| spath input=Message 
| rename XmlEventData.* as * 
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter 
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

### Example 2: TGT Requests for Accounts With Pre-Auth Disabled

**Timeframe**: `earliest=1690392745 latest=1690393283`

```spl
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

### Explanation of Splunk Search Components

1. **Filtering by Index and Event Codes**: Limits search to specific indices and event codes, targeting TGT and TGS requests.
2. **Regular Expressions (rex)**: Used to extract specific information such as usernames and IP addresses.
3. **Time Binning (bin)**: Groups events into time intervals for pattern analysis.
4. **Transactions**: Used to link related events, such as a TGS request without a following logon event.