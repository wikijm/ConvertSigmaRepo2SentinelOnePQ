```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rd.exe" or src.process.image.path="*rudesktop*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RuDesktop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rd.exe
    - rudesktop*.exe
  condition: selection
id: 26af703f-9c35-4356-a7d5-01a61b9e981f
status: experimental
description: Detects potential processes activity of RuDesktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RuDesktop
level: medium
```
