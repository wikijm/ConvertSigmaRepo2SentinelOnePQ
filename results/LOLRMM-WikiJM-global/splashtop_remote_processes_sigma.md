```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "strwinclt.exe" or src.process.image.path="*Splashtop_Streamer_Windows*.exe" or src.process.image.path contains "SplashtopSOS.exe" or src.process.image.path contains "sragent.exe" or src.process.image.path contains "srmanager.exe" or src.process.image.path contains "srserver.exe" or src.process.image.path contains "srservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop Remote RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - strwinclt.exe
    - Splashtop_Streamer_Windows*.exe
    - SplashtopSOS.exe
    - sragent.exe
    - srmanager.exe
    - srserver.exe
    - srservice.exe
  condition: selection
id: eeafd28d-ed54-4904-b5e0-81c88109d0ac
status: experimental
description: Detects potential processes activity of Splashtop Remote RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop Remote
level: medium
```
