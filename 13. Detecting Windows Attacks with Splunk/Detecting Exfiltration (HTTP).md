### Splunk Query for Detecting HTTP Exfiltration

```spl
index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
```

### Query Breakdown

1. **Data Source Selection**:
   - `index="cobaltstrike_exfiltration_http"`: Filters logs within the `cobaltstrike_exfiltration_http` index, which captures suspected exfiltration activity.
   - `sourcetype="bro:http:json"`: Focuses on Zeek HTTP logs formatted in JSON, which allows us to examine HTTP requests and responses.
   - `method=POST`: Filters only HTTP POST requests since they are commonly used for data exfiltration in the body of the request.

2. **Aggregating Data Volume**:
   - `| stats sum(request_body_len) as TotalBytes by src, dest, dest_port`: Aggregates the total data transferred in the POST body for each source IP (`src`), destination IP (`dest`), and destination port (`dest_port`).
     - `request_body_len` represents the length of the POST request body in bytes, which includes any data potentially exfiltrated.
     - `sum(request_body_len)`: Calculates the total volume of data sent in the POST body to each destination.

3. **Converting Data Size**:
   - `| eval TotalBytes = TotalBytes/1024/1024`: Converts the total data volume from bytes to megabytes (MB) for easier analysis.