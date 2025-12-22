```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "todesk.exe" or src.process.image.path contains "ToDesk_Service.exe" or src.process.image.path contains "ToDesk_Setup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ToDesk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - todesk.exe
    - ToDesk_Service.exe
    - ToDesk_Setup.exe
  condition: selection
id: a7014b31-abf1-41ae-aeff-0bed5bf0062e
status: experimental
description: Detects potential processes activity of ToDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ToDesk
level: medium
```
