<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized Tor Browser Usage

## Platforms and Languages Leveraged
- Windows 11 Virtual Machine
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser Portable

## Scenario
Management requested a threat hunt to determine whether Tor Browser was used on a corporate Windows endpoint. Tor Browser usage can allow users to bypass normal web filtering, conceal browsing activity, and establish encrypted connections through the Tor network.
The hunt focused on the endpoint `win-11-mde` and the account `azureuser`. The investigation reviewed file, process, and network telemetry related to Tor Browser activity. The goal was to determine whether Tor Browser was downloaded, installed or extracted, executed, and used to initiate network connections.

> Note: This report only includes activity related to the Tor Browser threat hunt.


### High-Level Tor-Related IoC Discovery Plan
- Check `DeviceFileEvents` for Tor-related file activity, including installer files, extracted Tor files, shortcuts, and suspicious files created around the same time.
- Check `DeviceProcessEvents` for Tor Browser installation, extraction, and execution activity.
- Check `DeviceNetworkEvents` for outbound connections from `tor.exe` or Tor Browser's Firefox process over known Tor-related ports.
- Correlate file, process, and network activity into a single chronological timeline.

---
## Hunt Scope
- Field	Value
  - Device	`win-11-mde`
  - User	`azureuser`
  - Initial event time	`2026-05-26T14:42:56.3208383Z`
  - Main installer observed	`tor-browser-windows-x86_64-portable-15.0.14.exe`
  - Tor Browser path observed	`C:\Users\azureuser\Desktop\Tor Browser\`
  - Primary Tor executable	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
> Timestamp note: The exported CSV logs displayed local EDT timestamps. This report normalizes the timeline to UTC to match the Advanced Hunting timestamps used in the hunt notes.
---
## Steps Taken
1. Searched the `DeviceFileEvents` Table
I searched `DeviceFileEvents` for Tor-related file activity on `win-11-mde` beginning at the first observed event time. The results showed that the Tor Browser portable installer appeared in the user's Downloads folder, was deleted shortly after, and Tor Browser files were then created under the user's Desktop path.
The file activity included the Tor executable `tor.exe`, Tor Browser shortcut files, and Tor-related license/documentation files. The hunt notes also identified a suspicious file named `Darkweb_shopping list.txt` created on the Desktop at `2026-05-26T17:49:41.9425401Z`.
> Evidence note: `DeviceFileEvents` confirms the installer appeared, was created, and was deleted in the Downloads folder. The logs support Tor Browser extraction or installation to the Desktop, but the file events alone do not prove the exact download mechanism.
Query used to locate events:
```kql
DeviceFileEvents
| where DeviceName == "win-11-mde"
| where FileName startswith "tor"
| where Timestamp >= datetime(2026-05-26T14:42:56.3208383Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
#### Key findings:
- UTC Timestamp	Action	File	Path
  - `2026-05-26T14:42:56Z`	File renamed	`tor-browser-windows-x86_64-portable-15.0.14.exe`	`C:\Users\azureuser\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe`
  - `2026-05-26T14:43:01Z`	File created	`tor-browser-windows-x86_64-portable-15.0.14.exe`	`C:\Users\azureuser\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe`
  - `2026-05-26T14:43:04Z`	File deleted	`tor-browser-windows-x86_64-portable-15.0.14.exe`	`C:\Users\azureuser\Downloads\tor-browser-windows-x86_64-portable-15.0.14.exe`
  - `2026-05-26T14:43:20Z`	File created	`tor.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
  - `2026-05-26T14:43:20Z`	File created	`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\`
  - `2026-05-26T14:43:25Z`	File created	`Tor Browser.lnk`	`C:\Users\azureuser\Desktop\Tor Browser\Tor Browser.lnk`
  - `2026-05-26T14:45:15Z`	File created	`Tor Browser.lnk`	`C:\Users\azureuser\Desktop\Tor Browser.lnk`
  - `2026-05-26T14:45:15Z`	File created	`Tor Browser.lnk`	`C:\Users\azureuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Tor Browser.lnk`
  - `2026-05-26T14:51:33Z`	File deleted	`tor.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
  - `2026-05-26T14:59:24Z`	File created	`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\`
  - `2026-05-26T17:49:41Z`	File created	`Darkweb_shopping list.txt`	Desktop path identified in hunt notes
 
2. Searched the `DeviceProcessEvents` Table for Installer Execution
I searched `DeviceProcessEvents` for the Tor Browser portable installer command line. The results showed that `azureuser` executed the Tor Browser portable installer from the Downloads folder using the `/S` silent flag.
Query used to locate the event:
```kql
DeviceProcessEvents
| where DeviceName == "win-11-mde"
| where AccountName == "azureuser"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.14.exe"
| where Timestamp >= datetime(2026-05-26T14:42:56.3208383Z)
| order by Timestamp asc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
#### Key finding:
- UTC Timestamp	User	Action	File	Command Line
  - `2026-05-26T14:59:00Z`	`azureuser`	Process created	`tor-browser-windows-x86_64-portable-15.0.14.exe`	`tor-browser-windows-x86_64-portable-15.0.14.exe /S`


3. Searched the `DeviceProcessEvents` Table for Tor Browser Execution
I searched for Tor-related processes including `tor.exe`, `firefox.exe`, and `tor-browser.exe`. The first observed Tor Browser launch occurred at `2026-05-26T14:45:15Z`, when multiple `firefox.exe` processes were created from the Tor Browser Desktop directory. Shortly afterward, `tor.exe` was launched from the Tor Browser path.
Additional Tor Browser process activity was observed around `2026-05-26T15:03:16Z` and again around `2026-05-26T17:43:27Z`, indicating multiple Tor Browser sessions.
Query used to locate events:
```kql
DeviceProcessEvents
| where DeviceName == "win-11-mde"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
#### Key findings:
- UTC Timestamp	User	Action	File	Path
  - `2026-05-26T14:45:15Z`	`azureuser`	Process created	`firefox.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\firefox.exe`
  - `2026-05-26T14:45:17Z`	`azureuser`	Process created	`tor.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
  - `2026-05-26T15:03:16Z`	`azureuser`	Process created	`firefox.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\firefox.exe`
  - `2026-05-26T15:03:19Z`	`azureuser`	Process created	`tor.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
  - `2026-05-26T17:43:27Z`	`azureuser`	Process created	`firefox.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\firefox.exe`
  - `2026-05-26T17:43:28Z`	`azureuser`	Process created	`tor.exe`	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`


4. Searched the `DeviceNetworkEvents` Table for Tor Network Connections
I searched `DeviceNetworkEvents` for network connections initiated by `tor.exe` or Tor Browser's Firefox process using known Tor-related ports. The results showed that `tor.exe` made multiple outbound connections to remote IP addresses over ports `9001`, `443`, and `80`. The browser process also attempted and later succeeded in connecting to the local Tor proxy on `127.0.0.1:9150`.

Query used to locate events:
```kql
DeviceNetworkEvents
| where DeviceName == "win-11-mde"
| where InitiatingProcessAccountName != @"system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443", "80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
#### Key findings:
- UTC Timestamp	User	Action	Remote IP	Remote Port	Process
  - `2026-05-26T14:45:49Z`	`azureuser`	Connection failed	`127.0.0.1`	`9150`	`firefox.exe`
  - `2026-05-26T14:45:52Z`	`azureuser`	Connection success	`18.18.82.18`	`9001`	`tor.exe`
  - `2026-05-26T14:45:53Z`	`azureuser`	Connection success	`79.141.174.124`	`9001`	`tor.exe`
  - `2026-05-26T14:45:53Z`	`azureuser`	Connection success	`135.181.19.99`	`80`	`tor.exe`
  - `2026-05-26T14:46:02Z`	`azureuser`	Connection success	`127.0.0.1`	`9150`	`firefox.exe`
  - `2026-05-26T15:03:27Z`	`azureuser`	Connection success	`138.197.166.92`	`443`	`tor.exe`
  - `2026-05-26T15:03:29Z`	`azureuser`	Connection success	`51.158.204.114`	`443`	`tor.exe`
  - `2026-05-26T15:03:29Z`	`azureuser`	Connection success	`64.65.0.100`	`443`	`tor.exe`
  - `2026-05-26T15:03:46Z`	`azureuser`	Connection failed	`79.116.0.2`	`9001`	`tor.exe`
> Important correction: The connection to `79.116.0.2` on port `9001` was a `ConnectionFailed` event in the export, not a successful connection.
---
### Chronological Event Timeline
#### UTC Timestamp	Event Category	Description	Evidence
- `2026-05-26T14:42:56Z`	File Activity	Tor Browser portable installer was renamed or appeared in the user's Downloads folder.	`FileRenamed` for `tor-browser-windows-x86_64-portable-15.0.14.exe`
- `2026-05-26T14:43:01Z`	File Activity	Tor Browser portable installer was created in the user's Downloads folder.	`FileCreated` for `tor-browser-windows-x86_64-portable-15.0.14.exe`
- `2026-05-26T14:43:04Z`	File Activity	Tor Browser portable installer was deleted from the Downloads folder.	`FileDeleted` for `tor-browser-windows-x86_64-portable-15.0.14.exe`
- `2026-05-26T14:43:20Z`	File Activity	Tor Browser files were created under the Desktop Tor Browser path, including `tor.exe` and Tor-related documentation/license files.	`FileCreated` events under `C:\Users\azureuser\Desktop\Tor Browser\`
- `2026-05-26T14:43:25Z`	File Activity	A Tor Browser shortcut was created inside the Desktop Tor Browser folder.	`FileCreated` for `Tor Browser.lnk`
- `2026-05-26T14:45:15Z`	File Activity	Tor Browser shortcuts were created on the Desktop and Start Menu.	`FileCreated` for `Tor Browser.lnk`
- `2026-05-26T14:45:15Z`	Process Activity	Tor Browser was launched for the first observed time through multiple `firefox.exe` process creations.	`ProcessCreated` for `firefox.exe`
- `2026-05-26T14:45:17Z`	Process Activity	The Tor service component started.	`ProcessCreated` for `tor.exe`
- `2026-05-26T14:45:49Z`	Network Activity	Tor Browser's Firefox process attempted to connect to the local Tor proxy.	`ConnectionFailed` to `127.0.0.1:9150` by `firefox.exe`
- `2026-05-26T14:45:52Z`	Network Activity	Tor service established outbound network activity on a Tor-related port.	`ConnectionSuccess` to `18.18.82.18:9001` by `tor.exe`
- `2026-05-26T14:45:53Z`	Network Activity	Tor service established another outbound connection on a Tor-related port.	`ConnectionSuccess` to `79.141.174.124:9001` by `tor.exe`
- `2026-05-26T14:45:53Z`	Network Activity	Tor service established outbound network activity over port `80`.	`ConnectionSuccess` to `135.181.19.99:80` by `tor.exe`
- `2026-05-26T14:46:02Z`	Network Activity	Tor Browser's Firefox process successfully connected to the local Tor proxy.	`ConnectionSuccess` to `127.0.0.1:9150` by `firefox.exe`
- `2026-05-26T14:46:03Z`	Process Activity	Additional Tor Browser Firefox process activity occurred after the local proxy connection succeeded.	`ProcessCreated` for `firefox.exe`
- `2026-05-26T14:51:33Z`	File Activity	`tor.exe` was deleted from the Desktop Tor Browser folder.	`FileDeleted` for `tor.exe`
- `2026-05-26T14:59:00Z`	Process Activity	The Tor Browser portable installer executed using the `/S` silent flag.	`ProcessCreated` for installer with `/S` command line
- `2026-05-26T14:59:24Z`	File Activity	Tor-related documentation/license files were created again, consistent with another extraction or installation event.	`FileCreated` for `tor.txt`, `Torbutton.txt`, and `Tor-Launcher.txt`
- `2026-05-26T15:03:16Z`	Process Activity	Tor Browser was launched again.	`ProcessCreated` for `firefox.exe`
- `2026-05-26T15:03:19Z`	Process Activity	The Tor service component started again.	`ProcessCreated` for `tor.exe`
- `2026-05-26T15:03:27Z`	Network Activity	Tor service established outbound activity over HTTPS.	`ConnectionSuccess` to `138.197.166.92:443` by `tor.exe`
- `2026-05-26T15:03:29Z`	Network Activity	Tor service established outbound activity over HTTPS.	`ConnectionSuccess` to `51.158.204.114:443` by `tor.exe`
- `2026-05-26T15:03:29Z`	Network Activity	Tor service established outbound activity over HTTPS.	`ConnectionSuccess` to `64.65.0.100:443` by `tor.exe`
- `2026-05-26T15:03:46Z`	Network Activity	Tor service attempted to connect to another remote host on port `9001`, but the connection failed.	`ConnectionFailed` to `79.116.0.2:9001` by `tor.exe`
- `2026-05-26T17:43:27Z`	Process Activity	Tor Browser was launched a third observed time.	`ProcessCreated` for `firefox.exe`
- `2026-05-26T17:43:28Z`	Process Activity	The Tor service component started during the third observed session.	`ProcessCreated` for `tor.exe`
- `2026-05-26T17:49:41Z`	File Activity	Hunt notes identified creation of `Darkweb_shopping list.txt` on the Desktop after Tor Browser usage.	File creation identified in hunt notes
---
### Indicators of Compromise and Notable Artifacts
#### Type	Indicator
- Device	`win-11-mde`
- User	`azureuser`
- Installer	`tor-browser-windows-x86_64-portable-15.0.14.exe`
- Installer SHA256	`f4048faea4c26e0241104ebb6cb0979937532961737ea5d87e5387196a8116ae`
- Tor executable	`C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- Tor executable SHA256	`1e02f3d7074d82d9ce76ea3dcf9a9d6fcc68f25745888c47e7eee88fd6b67cb9`
- Tor Browser Firefox path	`C:\Users\azureuser\Desktop\Tor Browser\Browser\firefox.exe`
- Tor Browser Firefox SHA256	`51534655250d77174ef98a69dd065d6714a39375795828688283e9a40d04be0d`
- Local Tor proxy activity	`127.0.0.1:9150`
- Remote IPs observed	`18.18.82.18`, `79.141.174.124`, `135.181.19.99`, `138.197.166.92`, `51.158.204.114`, `64.65.0.100`, `79.116.0.2`
- Remote ports observed	`9001`, `443`, `80`
- Suspicious user-created file from hunt notes	`Darkweb_shopping list.txt`


### Summary
- The investigation confirmed Tor Browser activity on the endpoint `win-11-mde` under the account `azureuser`.
- The activity began at approximately `2026-05-26T14:42:56Z`, when the Tor Browser portable installer appeared in the user's Downloads folder. Shortly afterward, Tor Browser files were created under `C:\Users\azureuser\Desktop\Tor Browser\`, including the primary Tor executable `tor.exe`, Tor Browser shortcuts, and Tor-related supporting files.
- At `2026-05-26T14:45:15Z`, Tor Browser was launched for the first observed time through the Tor Browser Firefox process. The Tor service component, `tor.exe`, started shortly after at `2026-05-26T14:45:17Z`. Network telemetry then showed activity consistent with Tor Browser usage, including local proxy communication on `127.0.0.1:9150` and outbound connections from `tor.exe` to remote IP addresses over ports `9001`, `443`, and `80`.
- The user launched Tor Browser multiple times, with additional sessions observed around `2026-05-26T15:03:16Z` and `2026-05-26T17:43:27Z`. The network evidence showed successful outbound Tor-related connections, as well as one failed connection attempt to `79.116.0.2:9001`.
- The hunt notes also identified the creation of a file named `Darkweb_shopping list.txt` on the Desktop at `2026-05-26T17:49:41Z`, shortly after the third observed Tor Browser launch. This file name is relevant to the investigation because it may indicate user activity or intent associated with dark web browsing.
- Overall, the file, process, and network evidence supports that Tor Browser was installed or extracted, launched multiple times, and used to initiate Tor-related network activity on `win-11-mde` by `azureuser`.
---
### Recommended Response
- Confirm whether Tor Browser usage is permitted by organizational policy.
- Preserve the exported hunt evidence and relevant MDE Advanced Hunting results.
- Review the contents and metadata of `Darkweb_shopping list.txt` if authorized.
- Remove Tor Browser from the endpoint if unauthorized.
- Review additional browsing, file, and network activity for the user `azureuser`.
- Notify management or the security lead according to the organization's acceptable
- use and incident response procedures.

### Final Determination
Tor Browser usage was confirmed on `win-11-mde` by `azureuser`. The evidence includes Tor Browser file creation, installer execution, Tor-related process execution, local proxy activity, and outbound connections initiated by `tor.exe`.
