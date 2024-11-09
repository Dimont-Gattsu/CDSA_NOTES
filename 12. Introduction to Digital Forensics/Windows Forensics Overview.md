## NTFS (New Technology File System)
NTFS is Microsoft’s file system, known for features that enhance performance, security, and data integrity. Key forensic artifacts include:

- **File Metadata**: Stores timestamps and file attributes, aiding in timeline analysis.
- **MFT Entries**: The Master File Table tracks metadata for all files, providing details even on deleted files.
- **File Slack and Unallocated Space**: Contains remnants of deleted files.
- **File Signatures**: Used to identify files even if extensions are altered.
- **USN Journal**: Logs file changes, supporting investigations into modifications.
- **LNK Files**: Shortcuts that reveal file and program access history.
- **Prefetch Files**: Indicate which programs were recently executed.
- **Registry Hives**: Record system configurations and can reveal traces of unauthorized modifications.
- **Shellbags**: Track folder navigation, highlighting accessed directories.
- **Thumbnail Cache**: Stores previews of recently viewed images and documents.
- **Recycle Bin**: Retains deleted files, providing insight into user actions.
- **Alternate Data Streams (ADS)**: Hidden data associated with files, sometimes exploited by malware.
- **Volume Shadow Copies**: Snapshots of the file system for data recovery.
- **Security Descriptors and ACLs**: Store file permissions, useful for analyzing access rights and security breaches.

## Windows Event Logs
Windows Event Logs record system and application events, capturing a range of user and system activities. Located at `C:\Windows\System32\winevt\logs`, these logs help detect:
- **System Errors**: Issues with the OS or applications.
- **Security Events**: Authentication attempts, policy changes, and access controls.
- **Application Events**: Logs from specific software, often useful in identifying exploitation attempts.

## Execution Artifacts
Execution artifacts document traces of program and script executions, providing insight into user actions and malware activities. Notable artifacts include:

- **Prefetch Files**: Track execution metadata (file paths, execution counts).
- **Shimcache**: Records program execution for compatibility; useful for identifying recent activity.
- **Amcache**: Stores executable details (file paths, digital signatures, last execution).
- **UserAssist**: Tracks user-executed applications, showing names, counts, and timestamps.
- **RunMRU Lists**: Logs recently executed commands and programs.
- **Jump Lists**: Document recent files and tasks associated with applications.
- **Shortcut (LNK) Files**: Provide executable paths, timestamps, and user interactions.
- **Recent Items**: Tracks recently accessed files.
- **Windows Event Logs**: Logs events tied to process creation and termination.

| Artifact       | Location / Registry Key                                      | Data Stored                                             |
|----------------|--------------------------------------------------------------|---------------------------------------------------------|
| Prefetch Files | `C:\Windows\Prefetch`                                        | Metadata on executed applications                       |
| Shimcache      | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\...AppCompatCache` | Program paths, timestamps                               |
| Amcache        | `C:\Windows\AppCompat\Programs\Amcache.hve`                  | Executable details                                      |
| UserAssist     | `HKEY_CURRENT_USER\Software\Microsoft\Windows\...UserAssist` | Application names, execution counts                     |
| RunMRU Lists   | `HKEY_CURRENT_USER\Software\Microsoft\Windows\...RunMRU`     | Recently executed commands                              |
| Jump Lists     | `%AppData%\Microsoft\Windows\Recent`                         | Recently accessed files                                 |
| Windows Event Logs | `C:\Windows\System32\winevt\Logs`                        | Logs of process events, creation, and termination       |

## Windows Persistence Artifacts
Persistence methods enable attackers to retain access to a system. These methods exploit system components like registry keys, scheduled tasks, and services.

### Registry Keys for Persistence
- **Run/RunOnce**:
  - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- **WinLogon Keys**:
  - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- **Startup Keys**:
  - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

### Scheduled Tasks (Schtasks)
Scheduled tasks in `C:\Windows\System32\Tasks` are stored as XML files, detailing task schedules and commands. These files should be reviewed for rogue or suspicious entries.

### Services
Windows services run processes in the background. Malicious actors may create or alter services to maintain persistence. The registry key for services is: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services`.

## Web Browser Forensics
Web browser analysis can reveal browsing habits, user interactions, and potentially harmful actions. Key artifacts include:

- **Browsing History**: Tracks sites visited, timestamps, and frequency.
- **Cookies**: Stores session details, preferences, and authentication data.
- **Cache**: Contains cached web pages and images, showing accessed sites even if history is cleared.
- **Bookmarks**: Indicates frequently accessed pages.
- **Download History**: Lists downloaded files, source URLs, and timestamps.
- **Autofill Data**: Stores data for forms (e.g., names, addresses).
- **Session Data**: Tracks active sessions, tabs, and open windows.
- **Extensions and Add-ons**: List of installed extensions and their configurations.

## SRUM (System Resource Usage Monitor)
Introduced in Windows 8, SRUM tracks application and resource usage. Located in `C:\Windows\System32\sru\sru.db`, this SQLite database records application profiles and resource usage, aiding in:

- **Application Profiling**: Shows executed applications and their paths.
- **Resource Consumption**: Logs CPU, network, and memory usage.
- **Timeline Reconstruction**: Builds a timeline of application use and system events.
- **User and System Context**: Ties activities to specific users, helping in identifying threat actors.
- **Malware Detection**: Tracks unusual application or resource patterns, which may indicate malware.
- **Incident Response**: Provides rapid insights into recent activities for quick threat response.