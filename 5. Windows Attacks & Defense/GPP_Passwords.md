## Description

SYSVOL is a network share on all Domain Controllers, containing logon scripts, group policy data, and other required domain-wide data. Active Directory stores all group policies in `\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`. With the release of Windows Server 2008, Group Policy Preferences (GPP) introduced the ability to store and use credentials in several scenarios. Active Directory stores these in the policies directory in SYSVOL.

During engagements, we might encounter scheduled tasks and scripts executed under a specific user, containing the username and an encrypted version of the password in XML policy files. The encryption key that Active Directory uses to encrypt these XML files was released publicly, allowing anyone to decrypt credentials in the policy files. Since SYSVOL is accessible to all `Authenticated Users` in the domain, anyone with access can decrypt the credentials.

Microsoft published the AES private key on MSDN. Here’s an example of an XML file containing an encrypted password, where the property is named `cpassword`.

## Attack

To abuse GPP Passwords, we use the `Get-GPPPassword` function from **PowerSploit**, which parses XML files in SYSVOL’s Policies folder, finds those with the `cpassword` property, and decrypts them:

```powershell
PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1
PS C:\Users\bob\Downloads> Get-GPPPassword

UserName  : svc-iis
NewName   : [BLANK]
Password  : abcd@123
Changed   : [BLANK]
File      : \\EAGLE.LOCAL\SYSVOL\eagle.local\Policies\{73C66DBB-81DA-44D8-BDEF-20BA2C27056D}\Machine\Preferences\Groups\Groups.xml
NodeName  : Groups
Cpassword : qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80
```

## Prevention

Once the encryption key was made public and began being exploited, Microsoft released **KB2962486** in 2014 to prevent caching credentials in GPP. However, the patch does not clear existing credentials, only prevents the caching of new ones. 

- Environments created pre-2014 may still have cached credentials.
- Regularly assess and review the environment to ensure no credentials are exposed.

## Detection

There are two main detection techniques for this attack:

1. **Auditing File Access to XML with Credentials**:
    - Monitoring access to these XML files is a good indicator of malicious intent if no legitimate reason exists for accessing these files.
    - Generate an event when a user reads the file by enabling auditing.
    - Each access will generate **Event ID 4663**.

2. **Logon Attempts with Exposed Credentials**:
    - Logon attempts (successful or failed) with the exposed service account credentials can trigger events:
      - **Event ID 4624** (successful logon)
      - **Event ID 4625** (failed logon)
      - **Event ID 4768** (TGT requested).

    Successful logons, especially from unexpected locations, can be correlated with known usage locations of service accounts.

## Honeypot

Setting up a trap account is a good detection strategy:

- Use a **service account** with an incorrect password as a honeypot.
- Ensure the honeypot has properties that make it appear legitimate:
  - The password is old.
  - Last password change predates the modification of the GPP XML file.
  - The account simulates logon activity (via a dummy task).

If any failed or successful logon attempts with this account occur (outside of the dummy task), it may indicate malicious activity.

### Relevant Event IDs for Failed Logons with Honeypot

- **4625** - Failed logon.
- **4771** - Kerberos pre-authentication failure.
- **4776** - NTLM authentication failure.

By leveraging honeypot accounts, you can detect potential attacks while minimizing the risk of false positives.
