```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\\Program Files (x86)\\ScreenConnect Client (Random)\\ScreenConnect.ClientService.exe" or src.process.image.path contains "Remote Workforce Client.exe" or src.process.image.path contains "\*\\ScreenConnect.ClientService.exe" or src.process.image.path contains "\*\\ScreenConnect.WindowsClient.exe" or src.process.image.path="*screenconnect*.exe" or src.process.image.path contains "screenconnect.windowsclient.exe" or src.process.image.path contains "Remote Workforce Client.exe" or src.process.image.path="*screenconnect*.exe" or src.process.image.path="*ConnectWiseControl*.exe" or src.process.image.path="*connectwise*.exe" or src.process.image.path contains "screenconnect.windowsclient.exe" or src.process.image.path contains "screenconnect.clientservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\Program Files (x86)\ScreenConnect Client (Random)\ScreenConnect.ClientService.exe
    - Remote Workforce Client.exe
    - '*\*\ScreenConnect.ClientService.exe'
    - '*\*\ScreenConnect.WindowsClient.exe'
    - screenconnect*.exe
    - screenconnect.windowsclient.exe
    - Remote Workforce Client.exe
    - screenconnect*.exe
    - ConnectWiseControl*.exe
    - connectwise*.exe
    - screenconnect.windowsclient.exe
    - screenconnect.clientservice.exe
  condition: selection
id: bc9c7d89-4f55-4a5b-beb2-e4f6ad488fec
status: experimental
description: Detects potential processes activity of ScreenConnect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ScreenConnect
level: medium
```
