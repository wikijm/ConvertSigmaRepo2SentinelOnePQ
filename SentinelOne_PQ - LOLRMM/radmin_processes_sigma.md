```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\Program Files (x86)\Radmin Viewer 3\Radmin.exe" or src.process.image.path contains "C:\Windows\SysWOW64\rserver30\rserver3.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RAdmin RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\Program Files (x86)\Radmin Viewer 3\Radmin.exe
    - C:\Windows\SysWOW64\rserver30\rserver3.exe
  condition: selection
id: b47e3faf-70e8-4067-b211-000156df756b
status: experimental
description: Detects potential processes activity of RAdmin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RAdmin
level: medium
```
