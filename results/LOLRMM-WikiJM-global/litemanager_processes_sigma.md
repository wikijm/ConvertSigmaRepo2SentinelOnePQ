```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "lmnoipserver.exe" or src.process.image.path contains "ROMFUSClient.exe" or src.process.image.path contains "romfusclient.exe" or src.process.image.path contains "romviewer.exe" or src.process.image.path contains "romserver.exe" or src.process.image.path contains "ROMServer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential LiteManager RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - lmnoipserver.exe
    - ROMFUSClient.exe
    - romfusclient.exe
    - romviewer.exe
    - romserver.exe
    - ROMServer.exe
  condition: selection
id: 8dca1aac-5754-4637-b668-04e7689f767b
status: experimental
description: Detects potential processes activity of LiteManager RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LiteManager
level: medium
```
