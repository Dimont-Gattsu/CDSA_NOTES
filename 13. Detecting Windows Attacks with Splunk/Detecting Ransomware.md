Ransomware can be detected by monitoring specific behaviors, such as excessive file overwrites and file renaming with distinct extensions. Here are two Splunk searches that identify these patterns:

---

### Detecting Excessive File Overwrite Operations

This query detects ransomware based on a high number of `SMB::FILE_OPEN` and `SMB::FILE_RENAME` actions within short intervals, a common ransomware characteristic:

```spl
index="ransomware_open_rename_sodinokibi" sourcetype="bro:smb_files:json" 
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30 
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```

#### Search Breakdown:
- **Index and Action Filtering**: Filters for entries in `ransomware_open_rename_sodinokibi` index with SMB actions of `FILE_OPEN` and `FILE_RENAME`.
- **5-Minute Time Bins**: Groups results in 5-minute intervals.
- **Counting Events**: Counts actions by `source` in each time bin, focusing on intervals with more than 30 actions.
- **Event Aggregation**: Aggregates results to check if both actions (`FILE_OPEN` and `FILE_RENAME`) are present within the time bin.
- **Flagging Potential Ransomware**: Flags results where both actions appear at least 100 times within the 5-minute bin, signaling excessive file activity.

---

### Detecting Excessive File Renaming with New Extensions

This search focuses on ransomware’s habit of renaming files by adding unique extensions, helping identify possible ransomware-encrypted files:

```spl
index="ransomware_new_file_extension_ctbl_ocker" sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME" 
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort -count
```

#### Search Breakdown:
- **Index, Action, and Time Filtering**: Limits results to file renames within 5-minute time bins.
- **Extracting Extensions**: Uses regex to extract extensions from `name` and `prev_name` fields.
- **Filtering Extension Changes**: Keeps only records where the file extension has changed.
- **Aggregating Results**: Counts occurrences by `source`, `new_file_name_extension`, and originating IP.
- **Flagging Potential Ransomware**: Filters for cases where over 20 files in a 5-minute bin are renamed with the same new extension, as ransomware often applies a uniform extension during encryption.

---

### Additional Resources for Ransomware Detection:
These resources provide lists of known ransomware extensions and naming patterns:
- [Ransomware Extensions Spreadsheet](https://docs.google.com/spreadsheets/d/e/2PACX-1vRCVzG9JCzak3hNqqrVCTQQIzH0ty77BWiLEbDu-q9oxkhAamqnlYgtQ4gF85pF6j6g3GmQxivuvO1U/pubhtml)
- [Corelight’s Detect-Ransomware-Filenames Repository](https://github.com/corelight/detect-ransomware-filenames)
- [Experiant’s FSRM Ransomware Extensions](https://fsrm.experiant.ca/)