```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\rclone.exe")
```


# Original Sigma Rule:
```yaml
title: Potential rclone RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\rclone.exe'
  condition: selection
id: d722606f-8f80-42b8-9ac2-1fb8d5cdb42e
status: experimental
description: Detects potential processes activity of rclone RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of rclone
level: medium
```
