```sql
// Translated content (automatically translated on 03-05-2025 10:24:52):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "mikogo.exe" or src.process.image.path contains "mikogo-starter.exe" or src.process.image.path contains "mikogo-service.exe" or src.process.image.path contains "mikogolauncher.exe" or src.process.image.path contains "\Mikogo-Service.exe" or src.process.image.path contains "\Mikogo-Screen-Service.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Mikogo RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mikogo.exe
    - mikogo-starter.exe
    - mikogo-service.exe
    - mikogolauncher.exe
    - '*\Mikogo-Service.exe'
    - '*\Mikogo-Screen-Service.exe'
  condition: selection
id: 2d03f8d5-126b-4b10-8e69-c7408a861cc0
status: experimental
description: Detects potential processes activity of Mikogo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Mikogo
level: medium
```
