```sql
// Translated content (automatically translated on 25-06-2025 00:54:24):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "qq.exe" or src.process.image.path contains "QQProtect.exe" or src.process.image.path contains "qqpcmgr.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential QQ IM-remote assistance RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - qq.exe
    - QQProtect.exe
    - qqpcmgr.exe
  condition: selection
id: d9d973a5-c10a-425e-8bbd-585dd3c24015
status: experimental
description: Detects potential processes activity of QQ IM-remote assistance RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of QQ IM-remote assistance
level: medium
```
