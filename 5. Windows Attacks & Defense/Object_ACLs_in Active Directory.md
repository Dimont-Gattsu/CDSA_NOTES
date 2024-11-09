## Description
In Active Directory (AD), **Access Control Lists (ACLs)** determine who can access specific objects and the type of access they have. Each ACL has multiple **Access Control Entries (ACEs)** that define the trustee and access type. ACLs are critical not only for access control but also for auditing attempts on securable objects in AD. Examples of ACL delegations include allowing non-admin users specific privileges, like resetting passwords or modifying group memberships.

In practical AD environments, misconfigurations in ACLs are common and may include:
- Domain users with Administrator access to servers.
- Overly permissive permissions, allowing "Everyone" full rights.
- Domain users having access to computer extended properties, such as LAPS passwords.

## Attack: Identifying Abusable ACLs
Tools like **BloodHound** and **SharpHound** can help visualize relationships and identify potential ACL misconfigurations. For instance:
```powershell
.\SharpHound.exe -c All
```

The scan results (ZIP file) from **SharpHound** can be analyzed in BloodHound to discover escalation paths. Focusing on user "Bob" reveals that:
1. **Full Rights over User Anni**: Bob can modify Anni's attributes (e.g., adding an SPN for Kerberoasting or resetting her password).
2. **Control over Server01**: Bob can retrieve the local administrator password or leverage Resource-Based Kerberos Delegation, especially since Server01 is trusted for Unconstrained Delegation.

**ADACLScanner** is another tool that can help generate DACL and SACL reports to detect similar issues.

## Prevention
1. **Continuous Assessment**: Regularly review AD for misconfigurations and abusable ACLs.
2. **Privilege Education**: Train privileged users on best practices to prevent accidental privilege delegation.
3. **Automate Access Management**: Streamline access assignments and restrict privilege modifications to reduce the risk of unintended access rights.

## Detection
Several events can indicate ACL abuse:
- **Event ID 4738** ("A user account was changed"): Logs when a user is modified, but without details (e.g., SPN additions).
- **Event ID 4724**: Captures password reset events, potentially after ACL abuse.
- **Event ID 4742**: Logs when a computer object is modified, useful for detecting suspicious changes on servers.

Naming conventions for privileged users (e.g., "adminxxxx") can also help identify unauthorized modifications by non-privileged users.

## Honeypot Strategy
Misconfigured ACLs can also act as a detection mechanism:
1. **High ACL Assignment to Honeypot Accounts**: Assign high permissions to honeypot accounts with exposed credentials to lure attackers.
2. **Modifiable Honeypot User**: Allow general users to modify a designated honeypot account. Any activity involving this account (e.g., event ID 4738) should trigger alerts.

An example detection mechanism could involve monitoring changes to Anni’s account by Bob. Any suspicious modification by Bob to Anni’s account or Server01 can trigger alerts and initiate forensic investigations if suspicious activity is confirmed.

---
**Note**: Implementing detection mechanisms, especially for honeypots, helps maintain visibility over unauthorized changes and can preemptively alert security teams to potential privilege escalation attempts.
