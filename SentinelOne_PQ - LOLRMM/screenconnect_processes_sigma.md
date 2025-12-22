```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ScreenConnect.ClientService.exe" or src.process.image.path contains "Remote Workforce Client.exe" or src.process.image.path contains "ScreenConnect.ClientService.exe" or src.process.image.path contains "ScreenConnect.WindowsClient.exe" or src.process.image.path="*screenconnect*.exe" or src.process.image.path contains "screenconnect.windowsclient.exe" or src.process.image.path contains "Remote Workforce Client.exe" or src.process.image.path="*screenconnect*.exe" or src.process.image.path="*ConnectWiseControl*.exe" or src.process.image.path="*connectwise*.exe" or src.process.image.path contains "screenconnect.windowsclient.exe" or src.process.image.path contains "screenconnect.clientservice.exe") or (tgt.process.image.path contains "ScreenConnect.ClientService.exe" or tgt.process.image.path contains "Remote Workforce Client.exe" or tgt.process.image.path contains "ScreenConnect.ClientService.exe" or tgt.process.image.path contains "ScreenConnect.WindowsClient.exe" or tgt.process.image.path="*screenconnect*.exe" or tgt.process.image.path contains "screenconnect.windowsclient.exe" or tgt.process.image.path contains "Remote Workforce Client.exe" or tgt.process.image.path="*screenconnect*.exe" or tgt.process.image.path="*ConnectWiseControl*.exe" or tgt.process.image.path="*connectwise*.exe" or tgt.process.image.path contains "screenconnect.windowsclient.exe" or tgt.process.image.path contains "screenconnect.clientservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool Process Activity
id: 3c95a0d7-14e3-4464-90a1-234b5a686fac
status: experimental
description: |
    Detects potential processes activity of ScreenConnect RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - ScreenConnect.ClientService.exe
            - Remote Workforce Client.exe
            - ScreenConnect.ClientService.exe
            - ScreenConnect.WindowsClient.exe
            - screenconnect*.exe
            - screenconnect.windowsclient.exe
            - Remote Workforce Client.exe
            - screenconnect*.exe
            - ConnectWiseControl*.exe
            - connectwise*.exe
            - screenconnect.windowsclient.exe
            - screenconnect.clientservice.exe
    selection_image:
        Image|endswith:
            - ScreenConnect.ClientService.exe
            - Remote Workforce Client.exe
            - ScreenConnect.ClientService.exe
            - ScreenConnect.WindowsClient.exe
            - screenconnect*.exe
            - screenconnect.windowsclient.exe
            - Remote Workforce Client.exe
            - screenconnect*.exe
            - ConnectWiseControl*.exe
            - connectwise*.exe
            - screenconnect.windowsclient.exe
            - screenconnect.clientservice.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ScreenConnect
level: medium
```
