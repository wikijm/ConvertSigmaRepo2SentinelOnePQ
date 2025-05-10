```sql
// Translated content (automatically translated on 10-05-2025 01:26:16):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "aeroadmin.exe" or src.process.image.path contains "AeroAdmin.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential AeroAdmin RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - aeroadmin.exe
    - AeroAdmin.exe
  condition: selection
id: bc9952c3-2d21-418e-9eed-a1d0450ee0c1
status: experimental
description: Detects potential processes activity of AeroAdmin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AeroAdmin
level: medium
```
