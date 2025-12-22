```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "level-windows-amd64.exe" or src.process.image.path contains "level.exe" or src.process.image.path contains "level-remote-control-ffmpeg.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Level.io RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - level-windows-amd64.exe
    - level.exe
    - level-remote-control-ffmpeg.exe
  condition: selection
id: b7c6d269-7610-4165-801e-5e4473915c75
status: experimental
description: Detects potential processes activity of Level.io RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Level.io
level: medium
```
