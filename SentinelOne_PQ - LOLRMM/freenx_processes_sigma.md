```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\*\nxplayer.exe" or src.process.image.path contains "\nxplayer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential FreeNX RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\*\nxplayer.exe
    - '*\nxplayer.exe'
  condition: selection
id: a8679551-7b77-4937-9b0d-d58e81caf27f
status: experimental
description: Detects potential processes activity of FreeNX RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FreeNX
level: medium
```
