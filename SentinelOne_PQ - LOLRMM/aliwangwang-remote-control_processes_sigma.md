```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "alitask.exe")
```


# Original Sigma Rule:
```yaml
title: Potential AliWangWang-remote-control RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - alitask.exe
  condition: selection
id: bda23e7b-9c5e-441b-b9bf-e30906c7cc3d
status: experimental
description: Detects potential processes activity of AliWangWang-remote-control RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AliWangWang-remote-control
level: medium
```
