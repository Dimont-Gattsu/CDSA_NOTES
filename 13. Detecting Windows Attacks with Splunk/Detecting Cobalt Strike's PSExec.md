## Splunk Query for Detecting Cobalt Strike’s PSExec

The following query detects the specific behavior patterns associated with Cobalt Strike’s `psexec` tool, which involves opening executable files over SMB in specific paths typically used for administrative tasks.

```spl
index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN" 
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```

### Query Breakdown

1. **Data Source Selection**:
   - `index="cobalt_strike_psexec"`: Searches within the specified index for logs related to Cobalt Strike `psexec` activity.
   - `sourcetype="bro:smb_files:json"`: Filters events to include only those that match the `bro:smb_files:json` sourcetype, which represents SMB file operation logs captured by Zeek.

2. **Filtering for File Open Actions**:
   - `action="SMB::FILE_OPEN"`: This narrows the search to events where a file was opened over SMB, as `psexec` typically opens an executable file on the target system.

3. **Suspicious File Names**:
   - `name IN ("*.exe", "*.dll", "*.bat")`: Filters events to focus on file types commonly associated with executable code, such as `.exe`, `.dll`, and `.bat` files. These file types are typical payloads that attackers use to deploy malicious services.

4. **Administrative SMB Paths**:
   - `path IN ("*\\c$", "*\\ADMIN$")`: This filters for SMB activity on administrative shares commonly used for remote administration and file transfers. The paths `C$` and `ADMIN$` are often accessed by `psexec` tools during payload deployment.

5. **File Size Greater Than Zero**:
   - `size>0`: Ensures that the event pertains to files that are not empty, as non-empty files are more likely to be executables or payloads rather than benign artifacts.

### Interpretation and Detection Strategy

This query is designed to detect a sequence of actions consistent with Cobalt Strike’s `psexec` execution:

- **Service Creation and Payload Delivery**: When `psexec` deploys a payload, it typically opens an executable file (e.g., `.exe`) on the target system over SMB. Filtering by specific paths (`C$` and `ADMIN$`) helps isolate activity on administrative shares, which is indicative of remote administration attempts.
- **Identifying Potential Malicious Activity**: Since legitimate administrative file operations typically do not involve arbitrary `.exe`, `.dll`, or `.bat` files on these paths, this search helps surface potential malicious activity. Additionally, focusing on non-zero file sizes eliminates irrelevant entries, further refining the results to show executable files likely linked to `psexec` operations.