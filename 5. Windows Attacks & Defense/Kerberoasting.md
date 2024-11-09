## Description

In Active Directory (AD), a **Service Principal Name (SPN)** is a unique identifier for service instances. SPNs allow Kerberos to authenticate clients to services without needing the service’s account name. When a Kerberos TGS service ticket is requested, it’s encrypted with the service account's NTLM hash.

**Kerberoasting** is a post-exploitation attack where attackers obtain a service ticket and perform offline password cracking on it. If successful, they can retrieve the service account password. Attack success hinges on the strength of the service account's password and the encryption algorithm used:

- **AES** (strongest but slow to crack)
- **RC4** (commonly vulnerable)
- **DES** (rarely used, only in very old environments)

Despite security recommendations to disable RC4 and DES, they are often still in use, making Kerberoasting a viable attack.

## Attack Path

1. **Extracting Crackable Tickets**: Using tools like Rubeus, tickets for all users with SPNs can be obtained:

    ```powershell
    PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt
    ```

    This will save extracted TGS hashes for each SPN user to `spn.txt`.

2. **Cracking Tickets**: The TGS hashes are then moved to a cracking tool (e.g., hashcat on Kali Linux).

    ```bash
    hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
    ```

    - **Hashcat Mode 13100**: Specifically for Kerberoastable TGS hashes.
    - **Password Cracking**: Utilizes a dictionary file (e.g., `passwords.txt`) to identify weak passwords.

3. **View Results**: Successfully cracked tickets reveal the service account password in plain text.

    ```bash
    cat cracked.txt
    ```

## Prevention

The attack’s success largely depends on weak service account passwords. To protect against Kerberoasting:

- **Use Strong Passwords**: Set long, random passwords (100+ characters).
- **Limit SPN Accounts**: Only assign SPNs where necessary and disable unused SPNs.
- **Group Managed Service Accounts (GMSA)**: Automatically managed and periodically rotated passwords.

## Detection

Kerberoasting leaves a footprint in Windows Event Log ID 4769, generated on TGS requests. Although monitoring every Event ID 4769 might be overwhelming, specific patterns can signal suspicious activity:

1. **Alert on RC4 Tickets**: If the environment only uses AES, flag Event ID 4769 with RC4 ticket requests.
2. **High Volume of TGS Requests**: Monitor for unusually high numbers of TGS requests from a single user/machine.
3. **Honeypot Accounts**: Configure a honeypot user account with no valid role but set privileges, ensuring it’s old and has an SPN. Any TGS request for this account is likely malicious.

## Honeypot Account Configuration

1. **Old User with Privileges**: Choose an account unused for 2+ years.
2. **Strong Password**: Ensure it’s uncrackable.
3. **SPN Registration**: Assign an SPN typical for production services (e.g., IIS or SQL).

Example honeypot setup:

- **User**: `svc-iam` with SPN but not actively used.

## Caution

Implementing honeypots for every detection type can expose a pattern to attackers. Choose detections that best suit the environment, balancing security and stealth.

---
