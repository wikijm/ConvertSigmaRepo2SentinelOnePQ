```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\IliAS.exe")
```


# Original Sigma Rule:
```yaml
title: Potential SysAid RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\IliAS.exe'
  condition: selection
id: 8ff7285f-da3e-4a2f-b941-e23f63c29013
status: experimental
description: Detects potential processes activity of SysAid RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SysAid
level: medium
```
