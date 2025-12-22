```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "issuser.exe" or src.process.image.path contains "landeskagentbootstrap.exe" or src.process.image.path contains "LANDeskPortalManager.exe" or src.process.image.path contains "ldinv32.exe" or src.process.image.path contains "ldsensors.exe" or src.process.image.path contains "\\issuser.exe" or src.process.image.path contains "\\softmon.exe" or src.process.image.path contains "\\tmcsvc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential LANDesk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - issuser.exe
    - landeskagentbootstrap.exe
    - LANDeskPortalManager.exe
    - ldinv32.exe
    - ldsensors.exe
    - '*\issuser.exe'
    - '*\softmon.exe'
    - '*\tmcsvc.exe'
  condition: selection
id: a2b98f5b-a4f2-4e25-a2f7-60aa5426888c
status: experimental
description: Detects potential processes activity of LANDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LANDesk
level: medium
```
