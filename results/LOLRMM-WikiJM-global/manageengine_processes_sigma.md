```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "InstallShield Setup.exe" or src.process.image.path contains "ManageEngine_Remote_Access_Plus.exe" or src.process.image.path contains "\\dcagentservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ManageEngine RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - InstallShield Setup.exe
    - ManageEngine_Remote_Access_Plus.exe
    - '*\dcagentservice.exe'
  condition: selection
id: 829a2556-2fa1-4ddd-bd0c-a3c6318a9596
status: experimental
description: Detects potential processes activity of ManageEngine RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ManageEngine
level: medium
```
