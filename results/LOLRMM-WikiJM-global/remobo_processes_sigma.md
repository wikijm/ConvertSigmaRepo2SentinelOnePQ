```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "remobo.exe" or src.process.image.path contains "remobo_client.exe" or src.process.image.path contains "remobo_tracker.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Remobo RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remobo.exe
    - remobo_client.exe
    - remobo_tracker.exe
  condition: selection
id: aba9003a-5514-4eea-a077-2b17cf760473
status: experimental
description: Detects potential processes activity of Remobo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remobo
level: medium
```
