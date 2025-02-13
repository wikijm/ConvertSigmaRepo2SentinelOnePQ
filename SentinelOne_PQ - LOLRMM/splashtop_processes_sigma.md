```sql
// Translated content (automatically translated on 14-11-2024 01:18:01):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "strwinclt.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - strwinclt.exe
  condition: selection
id: 7fb2bbef-d140-461d-aca3-9c0cfe6d3d4b
status: experimental
description: Detects potential processes activity of Splashtop RMM tool
author: LOLRMM Project
date: 2024-08-07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop
level: medium
```
