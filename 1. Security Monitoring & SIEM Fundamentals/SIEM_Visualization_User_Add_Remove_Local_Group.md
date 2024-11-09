## Objective
Create a visualization to monitor user additions or removals from the "Administrators" group from March 5th, 2023 to the present date.

## Steps

1. **Navigate to the Target System**
   - Access the SIEM tool via `http://[Target IP]:5601`.
   - Open the "Dashboard" from the side navigation.

2. **Edit Dashboard**
   - Click the "pencil" or edit icon to modify the dashboard.
   - Select "Create visualization" to start.

3. **Configure Visualization Settings**
   - **Filter Configuration**
     - Set up filters to focus on Event IDs `4732` (user added to group) and `4733` (user removed from group).
     - Filter events to only include changes involving the "Administrators" group.
   - **Index Pattern**
     - Specify `windows*` as the index pattern to use Windows-related logs.
   - **Search Bar Check**
     - Confirm `user.name.keyword` is present to ensure access to relevant data.
   - **Select Visualization Type**
     - Choose the "Table" option for the display.

4. **Table Configuration**
   - **Rows Settings**
     - Add "Rows" to display:
       - **User Involved** - account added or removed (`winlog.event_data.MemberSid.keyword`).
       - **Group Targeted** - confirm it’s the "Administrators" group (`group.name.keyword`).
       - **Action Taken** - whether the user was added or removed (`event.action.keyword`).
       - **Machine Name** - the host reporting the change (`host.name.keyword`).
       - **Count of Events** - set to "count" for the number of occurrences.
   - **Metrics**
     - Select "count" as the metric to populate the table.

5. **Set Date Range**
   - Apply a date filter from March 5th, 2023 to the current date to narrow the data scope.

6. **Save and Return**
   - Click "Save and return" to add the configured visualization to the dashboard.

---

The completed table will display:
- The user added or removed from the group.
- The group, ensuring it is the "Administrators" group.
- The action taken (added or removed).
- The machine where the action occurred.
- The count of additions or removals within the specified timeframe.

