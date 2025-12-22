```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\Box.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Box RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Box.exe'
  condition: selection
id: e7af44b5-c19f-460f-a717-35b07594b505
status: experimental
description: Detects potential processes activity of Box RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Box
level: medium
```
