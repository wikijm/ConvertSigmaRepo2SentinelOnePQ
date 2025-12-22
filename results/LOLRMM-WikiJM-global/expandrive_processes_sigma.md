```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "C:\\Users\*\\ExpanDrive.exe" or src.process.image.path contains "\\ExpanDrive.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ExpanDrive RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\Users\*\ExpanDrive.exe
    - '*\ExpanDrive.exe'
  condition: selection
id: 063831a9-cbe9-4699-bc06-29cfc716b55f
status: experimental
description: Detects potential processes activity of ExpanDrive RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ExpanDrive
level: medium
```
