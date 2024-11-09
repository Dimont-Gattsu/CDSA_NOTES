## Description

A Group Policy Object (GPO) is a virtual collection of policy settings that has a unique name. GPOs are widely used in Active Directory (AD) for configuration management. Each GPO contains policy settings linked to an Organizational Unit (OU) in AD to apply settings to objects within that OU or any child OU. GPOs can be restricted to specific objects or filtered, for example, by specifying an AD group or using a WMI filter.

When a new GPO is created, only Domain admins (and similar privileged roles) can modify it. However, different delegations within environments may allow less privileged accounts to perform edits on GPOs. Some organizations have GPOs that allow modifications by 'Authenticated Users' or 'Domain Users,' which means any compromised user account may allow attackers to alter these GPOs. Such modifications may include adding start-up scripts or scheduled tasks to execute a file, enabling adversaries to compromise computer objects in the OUs linked to the vulnerable GPOs.

Similarly, administrators may install software or configure start-up scripts through GPOs that rely on files located on network shares. If these shares are misconfigured, attackers may replace files with malicious versions. Even if the GPO permissions are intact, the attack can be executed through misconfigured NTFS permissions on deployed files.

## Attack

To abuse GPO permissions, an attacker can directly edit a GPO or replace a file in a network share used by the GPO.

## Prevention

1. **Lockdown GPO permissions:** Limit modification rights to a small group of trusted users or a specific account to prevent unauthorized GPO edits.
2. **Review GPO permissions:** Regularly review and automate hourly checks on GPO permissions to ensure no deviations from expected configurations.
3. **Secure network shares:** Avoid using files from network shares that can be modified by multiple users to prevent file replacement attacks.

## Detection

- **Event ID 5136:** This event ID logs GPO modifications if Directory Service Changes auditing is enabled. Detecting unexpected modifications to GPOs, especially by users without expected permissions, should raise an alert.

## Honeypot

Using a misconfigured GPO or file as a honeypot can be a strategy for detecting unauthorized modifications. However, it’s recommended only for mature environments capable of responding quickly to vulnerabilities. Consider the following guidelines for honeypot GPOs:

- Link the GPO only to non-critical servers.
- Monitor modifications continuously with automation in place.
- Unlink or disable the GPO if a modification is detected.

### Example PowerShell Script for GPO Modification Detection

This PowerShell script demonstrates automation for detecting and disabling accounts that modify a specified honeypot GPO. The honeypot GPO is identified by a GUID value, and the script disables any account associated with modifications detected every 15 minutes.

```powershell
# Define filter for the last 15 minutes
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)

# Search for event ID 5136 (GPO modified) in the past 15 minutes
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |`
Where-Object {$_.Properties[8].Value -match "CN={73C66DBB-81DA-44D8-BDEF-20BA2C27056D},CN=POLICIES,CN=SYSTEM,DC=EAGLE,DC=LOCAL"}

if($Logs){
    $emailBody = "Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified`r`n"
    $disabledUsers = @()
    ForEach($log in $logs){
        If(((Get-ADUser -identity $log.Properties[3].Value).Enabled -eq $true) -and ($log.Properties[3].Value -notin $disabledUsers)){
            Disable-ADAccount -Identity $log.Properties[3].Value
            $emailBody = $emailBody + "Disabled user " + $log.Properties[3].Value + "`r`n"
            $disabledUsers += $log.Properties[3].Value
        }
    }
    # Send an alert via email - complete the command below
    # Send-MailMessage
    $emailBody
}
```

If the honeypot GPO is modified, the script outputs the following, or sends an email alert if configured:

```
Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified
Disabled user bob
```

After disabling, Event ID 4725 logs the account disabling action.

---
