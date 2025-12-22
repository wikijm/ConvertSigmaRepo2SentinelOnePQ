```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\airexplorer.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Air Explorer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\airexplorer.exe'
  condition: selection
id: 24bbfdf2-d188-4297-9d25-d1cc73dd2a38
status: experimental
description: Detects potential processes activity of Air Explorer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Air Explorer
level: medium
```
