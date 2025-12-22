```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*tigervnc*.exe" or src.process.image.path contains "winvnc4.exe" or src.process.image.path contains "\\tvnserver.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential TigerVNC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - tigervnc*.exe
    - winvnc4.exe
    - '*\tvnserver.exe'
  condition: selection
id: af9eb98b-be96-42a9-b890-4149290c19ff
status: experimental
description: Detects potential processes activity of TigerVNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TigerVNC
level: medium
```
