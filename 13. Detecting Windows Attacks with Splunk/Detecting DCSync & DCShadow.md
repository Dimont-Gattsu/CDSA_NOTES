## DCSync

DCSync is a technique used by attackers to request domain replication data, effectively imitating a domain controller to extract password hashes from Active Directory Domain Controllers (DCs). This attack allows an attacker to obtain current and historical password hashes, which can then be used for further attacks, such as crafting Golden or Silver Tickets.

### Attack Steps

1. **Administrative Access**: The attacker gains administrative access to a domain-joined system or escalates privileges.
2. **Request Replication Data**: Using tools like Mimikatz, the attacker uses the `DRSGetNCChanges` interface to request domain replication data.
3. **Use of Extracted Hashes**: The attacker uses the acquired data to create Golden or Silver Tickets or conduct Pass-the-Hash attacks.

### Detection Opportunities

- **Event ID 4662**: This event logs DS-Replication-Get-Changes operations, necessary for detecting DCSync activities.
- **Audit Policy Configuration**: Ensure Advanced Audit Policy is configured for Directory Service Access (not enabled by default).

---

### Example Splunk Query: Detecting DCSync with Event ID 4662

**Description**: This search identifies Directory Service replication requests associated with DCSync by looking for the “Replicating Directory Changes” property in Event ID 4662.

**Timeframe**: `earliest=1690544278 latest=1690544280`

```spl
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

---

## DCShadow

DCShadow is an advanced attack that enables attackers to create unauthorized Active Directory changes without triggering standard logs. This tactic involves creating rogue domain controllers, which can modify AD objects and spread unauthorized changes across the domain.

### Attack Steps

1. **Administrative Access**: The attacker gains high privileges to register a rogue domain controller.
2. **Register Rogue DC**: The attacker registers a rogue DC and makes AD changes, such as adding users to the Domain Admins group.
3. **Replicate Changes**: The rogue DC replicates changes with legitimate DCs, spreading unauthorized modifications.

### Detection Opportunities

- **Event ID 4742**: This event captures changes to computer objects, including ServicePrincipalName (SPN) modifications.
- **New `nTDSDSA` Object**: Detect the addition of `nTDSDSA` objects in AD schema, typically associated with DCShadow.

---

### Example Splunk Query: Detecting DCShadow with Event ID 4742

**Description**: This query identifies changes to computer accounts associated with DCShadow by looking for modifications in the `ServicePrincipalName`.

**Timeframe**: `earliest=1690623888 latest=1690623890`

```spl
index=main earliest=1690623888 latest=1690623890 EventCode=4742 
| rex field=Message "(?P<gcspn>XX\/[a-zA-Z0-9\.\-\/]+)" 
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn 
| search gcspn=*
```

---

## Summary

DCSync and DCShadow are powerful techniques for attackers targeting Active Directory environments. By monitoring for specific event IDs and unusual changes in replication and computer object properties, security teams can enhance detection capabilities and mitigate the risks associated with these attacks.