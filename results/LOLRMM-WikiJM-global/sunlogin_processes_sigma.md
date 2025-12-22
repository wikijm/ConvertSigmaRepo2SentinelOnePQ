```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "OrayRemoteShell.exe" or src.process.image.path contains "OrayRemoteService.exe" or src.process.image.path="*sunlogin*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential SunLogin RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - OrayRemoteShell.exe
    - OrayRemoteService.exe
    - sunlogin*.exe
  condition: selection
id: 820431ec-1186-4462-b809-17dbc4603614
status: experimental
description: Detects potential processes activity of SunLogin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SunLogin
level: medium
```
