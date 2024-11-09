Here's a breakdown of this Splunk query, designed to detect activity related to the Zerologon attack by identifying unusual Netlogon operations within the logs:

---

### Splunk Query for Detecting Zerologon

```spl
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```

### Query Breakdown

1. **Data Source Selection**:
   - `index="zerologon"`: Focuses on events within the "zerologon" index, which is set up to capture Zerologon-related network activity.
   - `endpoint="netlogon"`: Filters events specific to the Netlogon endpoint, as Zerologon exploits this protocol.
   - `sourcetype="bro:dce_rpc:json"`: Targets Zeek logs specifically formatted as DCE-RPC (Distributed Computing Environment/Remote Procedure Call), which logs Netlogon traffic.

2. **Time Binning**:
   - `| bin _time span=1m`: Organizes events into one-minute intervals. This helps detect patterns within a short time frame, as Zerologon attacks typically occur within seconds.

3. **Filtering for Key Operations**:
   - `| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"`: This filter focuses on key operations associated with the Zerologon attack:
     - `NetrServerReqChallenge`: Used to initiate the challenge-response in the authentication sequence.
     - `NetrServerAuthenticate3`: Used to authenticate a client with the server.
     - `NetrServerPasswordSet2`: Used to change a machine’s password on the domain, which is exploited in Zerologon.

4. **Statistical Analysis**:
   - `| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h`: Aggregates events by time, source IP (`id.orig_h`), and destination IP (`id.resp_h`). It calculates:
     - `count`: Total number of occurrences of the specified operations.
     - `values(operation) as operation_values`: Lists unique operations for the given combination of source, destination, and time.
     - `dc(operation) as unique_operations`: Counts distinct operations performed, which helps ensure there are multiple types of operations.

5. **Filtering for Anomalous Patterns**:
   - `| where unique_operations >= 2 AND count>100`: Flags activity where:
     - Two or more unique operations are observed (indicating an unusual sequence related to Zerologon).
     - The total count exceeds 100, which suggests a potential brute force or abuse attempt, as typical Netlogon traffic would not involve such a high count in a brief period.