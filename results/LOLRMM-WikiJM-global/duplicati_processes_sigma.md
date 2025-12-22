```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "c:\\Program Files\*\\Duplicati.Server.exe" or src.process.image.path contains "\*\\Duplicati.Server.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Duplicati RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - c:\Program Files\*\Duplicati.Server.exe
    - '*\*\Duplicati.Server.exe'
  condition: selection
id: 270a1720-2a6c-43ab-8ff9-c694909ea6ae
status: experimental
description: Detects potential processes activity of Duplicati RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Duplicati
level: medium
```
