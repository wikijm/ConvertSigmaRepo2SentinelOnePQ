```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*oo-syspectr*.exe" or src.process.image.path contains "OOSysAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Syspectr RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - oo-syspectr*.exe
    - OOSysAgent.exe
  condition: selection
id: cee48c18-78d7-4b7b-ab00-7def87fb17c5
status: experimental
description: Detects potential processes activity of Syspectr RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Syspectr
level: medium
```
