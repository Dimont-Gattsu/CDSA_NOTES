## 1. Creating a Custom Splunk Application

### Step 1: Access Splunk Web
- Open your web browser and log in to Splunk Web.

### Step 2: Go to Manage Apps
- Navigate to the **Apps** menu at the top of the page, then select **Manage Apps**.

### Step 3: Create a New App
1. On the Apps page, click **Create app**.
2. Complete the following fields:
   - **Name**: Enter the app name, e.g., `Active Directory Attack Detection`.
   - **Folder name**: This should be similar to the app name, e.g., `AD_Attack_Detection`. This folder will be created under `$SPLUNK_HOME/etc/apps/`.
   - **Version**: Enter the initial version, e.g., `1.0.0`.
   - **Description**: Add a brief description, e.g., `Application for detecting Active Directory attacks`.
   - **Template**: Choose `barebones` from the dropdown.

3. Click **Save** to create the app. Your new app should now appear under **Apps**.

---

## 2. Understanding the Directory Structure

After creating the app, navigate to `$SPLUNK_HOME/etc/apps/AD_Attack_Detection`. Inside, you’ll find directories, each serving a specific purpose:

- `/bin`: Store custom scripts here.
- `/default`: Store default configuration files, views, dashboards, and navigation.
- `/local`: Store user-modified configurations for views, dashboards, and navigation.
- `/metadata`: Contains permission files.

---

## 3. Editing the Navigation File

1. Open the file `$SPLUNK_HOME/etc/apps/AD_Attack_Detection/default/data/ui/nav/default.xml` in a text editor.
2. The XML structure defines app navigation, with each `<view>` tag representing a view in the app bar. Here’s an example:

```xml
<nav search_view="search">
  <view name="search" default='true' />
  <view name="analytics_workspace" />
  <view name="datasets" />
  <view name="reports" />
  <view name="alerts" />
  <view name="dashboards" />
</nav>
```

- **search_view**: Specifies the default view.
- **default='true'**: Sets the default app homepage, e.g., the search view.

---

## 4. Creating a Dashboard

1. Navigate to **Dashboards** in your Splunk app.
2. Click **Create New Dashboard** and provide:
   - **Dashboard Name**: e.g., `AD Attack Dashboard`
   - **Description**: (optional)
   - **Permissions**: Set according to needs.
   - **Dashboard Type**: Choose `Classic Dashboards`.

3. Configure the dashboard with panels, inputs, and time range settings.
4. To reference inputs, use tokens enclosed in `$`, e.g., `$user$`.

### Dashboard Storage

The XML configuration for each dashboard is stored in `<AppPath>/local/data/ui/views/dashboard_title.xml`.

### Adding Dashboards to Navigation

1. Open `$SPLUNK_HOME/etc/apps/AD_Attack_Detection/default/data/ui/nav/default.xml`.
2. Add the dashboard title in the `<nav>` section to make it accessible in the app's navigation.

---

## 5. Restart Splunk

- Restart Splunk to apply the changes and see the new dashboard listed in the app’s navigation bar.

---

## 6. Grouping Dashboards in the Navigation Bar

To group multiple dashboards, use the `<collection>` tag in `default.xml`:

```xml
<collection label="AD Monitoring Dashboards">
  <view name="dashboard1" />
  <view name="dashboard2" />
</collection>
```

---

## 7. Updating an Existing App

To update the app with a pre-configured application file:

1. **Download** the `Detection-of-Active-Directory-Attacks.tar.gz` file from the Resources section.
2. Go to **Apps -> Manage Apps** and click **Install app from file**.
3. Browse for the file, check **Upgrade app** to overwrite the existing app, then click **Upload**.