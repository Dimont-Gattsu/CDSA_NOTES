## Objective
Create a visualization to monitor successful RDP logon attempts specifically related to service accounts.

## Steps

1. **Navigate to the Target System**
   - Access the SIEM tool via `http://[Target IP]:5601`.
   - Open the "Dashboard" from the side navigation.

2. **Edit Dashboard**
   - Click the "pencil" or edit icon to modify the dashboard.
   - Select "Create visualization" to begin.

3. **Configure Visualization Settings**
   - **Filter Configuration**
     - Set up a filter to focus on Event ID `4624` (successful logon attempts).
     - Filter logon type to `RemoteInteractive` using the `winlog.logon.type` field.
   - **Index Pattern**
     - Specify `windows*` as the index pattern to use Windows-related logs.
   - **Search Bar Check**
     - Confirm `user.name.keyword` is in the dataset to ensure field accuracy.
   - **Select Visualization Type**
     - Choose the "Table" option for the display.

4. **Table Configuration**
   - **Rows Settings**
     - Add "Rows" to display:
       - **Service Account** - `user.name` field (filtered for svc-* for service accounts).
       - **Machine** - reporting host machine (`host.hostname.keyword`).
       - **Initiating IP** - IP of the machine that initiated the logon (`related.ip.keyword`).
       - **Count of Events** - set to "count" to show event occurrences.
   - **Metrics**
     - Select "count" as the metric to populate the table.

5. **KQL Query for Service Accounts**
   - Use `user.name: svc-*` to limit results to service accounts starting with `svc-`.

6. **Save and Return**
   - Click "Save and return" to add the configured visualization to the dashboard.

---

The completed table will display:
- The service account used for the RDP logon.
- The machine that received the logon.
- The IP of the initiating machine.
- The count of successful RDP logon attempts.

