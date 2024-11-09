### Basic Searching
Example: `search index="main" "UNKNOWN"`

### Boolean and Comparison Operators
Example: `index="main" EventCode!=1`

### Fields Command
Exclude a field from results: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User`

### Table Command
Present results in a table: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image`

### Rename Command
Rename fields in results: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process`

### Dedup Command
Remove duplicate events: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image`

### Sort Command
Sort results: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time`

### Stats Command
Run statistical operations: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image`

### Chart Command
Create visualizations: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image`

### Eval Command
Create/redefine fields: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)`

### Rex Command
Extract fields with regex: `index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid`

### Lookup Command
Enrich data with external sources.

#### Example using `malware_lookup.csv`
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rex field=Image "(?P<filename>[^\\]+)$" | eval filename=lower(filename) | lookup malware_lookup.csv filename OUTPUTNEW is_malware | table filename, is_malware
```

### Inputlookup Command
Retrieve data from a lookup file: `| inputlookup malware_lookup.csv`

### Time Range Filter
Limit searches to specific times: `index="main" earliest=-7d EventCode!=1`

### Transaction Command
Group related events: `index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m | table Image | dedup Image`

### Subsearches
Nest searches: `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName`

## Data and Field Identification

- **Use SPL Commands**: To understand available data and fields.
  - `| eventcount summarize=false index=* | table index`
  - `| metadata type=sourcetypes`
  - `sourcetype="WinEventLog:Security" | table _raw`

- **Data Models**: Structure and understand data.

- **Pivot**: Interactive way to explore data without SPL queries.

Refer to [Splunk Documentation](https://docs.splunk.com/Documentation/SCS/current/SearchReference/Introduction) for more.
