### Description

Credentials exposed in network shares are (probably) the most encountered misconfiguration in Active Directory to date. Any medium/large enterprises will undoubtedly have exposed credentials, although it may also happen in small businesses. It almost feels like we are moving from "Don't leave your password on a post-it note on your screen" to "Don't leave unencrypted credentials and authorization tokens scattered everywhere".

We often find credentials in network shares within scripts and configuration files (batch, cmd, PowerShell, conf, ini, and config). In contrast, credentials on a user's local machine primarily reside in text files, Excel sheets, or Word documents. The main difference between the storage of credentials on shares and machines is that the former poses a significantly higher risk, as it may be accessible by every user. A network share may be accessible by every user for four main reasons:

1. One admin user initially creates the shares with properly locked down access but ultimately opens it to everyone. Another admin of the server could also be the culprit. Nonetheless, the share eventually becomes open to Everyone or Users, and recall that a server's Users group contains Domain users as its member in Active Directory environments. Therefore every domain user will have at least read access (it is wrongly assumed that adding 'Users' will give access to only those local to the server or Adm...

2. The administrator adding scripts with credentials to a share is unaware it is a shared folder. Many admins test their scripts in a scripts folder in the C:\ drive; however, if the folder is shared (for example, with Users), then the data within the scripts is also exposed on the network.

3. Another example is purposely creating an open share to move data to a server (for example, an application or some other files) and forgetting to close it later.

4. Finally, in the case of hidden shares (folders whose name ends with a dollar sign $), there is a misconception that users cannot find the folder unless they know where it exists; the misunderstanding comes from the fact that Explorer in Windows does not display files or folders whose name end with a $, however, any other tool will show it.

### Attack

The first step is identifying what shares exist in a domain. There are plenty of tools available that can achieve this, such as PowerView's `Invoke-ShareFinder`. This function allows specifying that default shares should be filtered out (such as c$ and IPC$) and also check if the invoking user has access to the rest of the shares it finds. The final output contains a list of non-default shares that the current user account has at least read access to:

```powershell
PS C:\Users\bob\Downloads> Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
```

Example Output:

```
\\DC2.eagle.local\NETLOGON      - Logon server share
\\DC2.eagle.local\SYSVOL        - Logon server share
\\WS001.eagle.local\Share       -
\\WS001.eagle.local\Users       -
\\Server01.eagle.local\dev$     -
\\DC1.eagle.local\NETLOGON      - Logon server share
\\DC1.eagle.local\SYSVOL        - Logon server share
```

A few automated tools exist, such as `SauronEye`, which can parse a collection of files and pick up matching words. However, because there are few shares in the playground, we will take a more manual approach (Living Off the Land) and use the built-in command `findstr` for this attack.

**Arguments:**

- `/s` forces to search the current directory and all subdirectories
- `/i` ignores case in the search term
- `/m` shows only the filename for a file that matches the term

**Example Commands:**

```powershell
PS Microsoft.PowerShell.Core\FileSystem::\\Server01.eagle.local\dev$> findstr /m /s /i "pass" *.bat
```

### Prevention

The best practice to prevent these attacks is to lock down every share in the domain so there are no loose permissions. Regular scans (e.g., weekly) on AD environments to identify any new open shares or credentials exposed in older ones are necessary.

### Detection

Understanding and analyzing users' behavior is the best detection technique for abusing discovered credentials in shares. Event IDs to monitor include:

- **4624** for successful logon
- **4768** for Kerberos TGT requests

### Honeypot

A honeypot user in AD environments: a semi-privileged username with a wrong password. Below is a good setup for the account:

- A service account created 2+ years ago, with the last password change at least one year ago.
- The account is still active in the environment.

Because the provided password is wrong, we would primarily expect failed logon attempts.

**Example Event IDs:**

- **4625** for failed logon
- **4771** for failed Kerberos pre-authentication
- **4776** for failed NTLM authentication
