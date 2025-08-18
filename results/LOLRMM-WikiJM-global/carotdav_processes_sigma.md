```sql
// Translated content (automatically translated on 18-08-2025 01:49:20):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\CarotDAV.exe")
```


# Original Sigma Rule:
```yaml
title: Potential CarotDAV RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\CarotDAV.exe'
  condition: selection
id: 7dcb3a6d-9092-45ae-88be-f56ec4b5d932
status: experimental
description: Detects potential processes activity of CarotDAV RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CarotDAV
level: medium
```
