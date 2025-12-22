```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "zaservice.exe" or src.process.image.path contains "ZMAgent.exe" or src.process.image.path contains "C:\*\\ZA_Access.exe" or src.process.image.path contains "ZohoMeeting.exe" or src.process.image.path contains "Zohours.exe" or src.process.image.path contains "zohotray.exe" or src.process.image.path contains "ZohoURSService.exe" or src.process.image.path contains "\\ZA_Access.exe" or src.process.image.path contains "Zaservice.exe" or src.process.image.path contains "za_connect.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Zoho Assist RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - zaservice.exe
    - ZMAgent.exe
    - C:\*\ZA_Access.exe
    - ZohoMeeting.exe
    - Zohours.exe
    - zohotray.exe
    - ZohoURSService.exe
    - '*\ZA_Access.exe'
    - Zaservice.exe
    - za_connect.exe
  condition: selection
id: 4d4a089c-d901-4d5d-8252-869a87d8a4d7
status: experimental
description: Detects potential processes activity of Zoho Assist RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Zoho Assist
level: medium
```
