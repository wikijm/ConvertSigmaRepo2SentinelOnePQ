```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "mikogo.exe" or src.process.image.path contains "mikogo-starter.exe" or src.process.image.path contains "mikogo-service.exe" or src.process.image.path contains "mikogolauncher.exe" or src.process.image.path contains "Mikogo-Service.exe" or src.process.image.path contains "Mikogo-Screen-Service.exe") or (tgt.process.image.path contains "mikogo.exe" or tgt.process.image.path contains "mikogo-starter.exe" or tgt.process.image.path contains "mikogo-service.exe" or tgt.process.image.path contains "mikogolauncher.exe" or tgt.process.image.path contains "Mikogo-Service.exe" or tgt.process.image.path contains "Mikogo-Screen-Service.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Mikogo RMM Tool Process Activity
id: bf492f20-25e6-4891-867d-2da09dbe45ab
status: experimental
description: |
    Detects potential processes activity of Mikogo RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - mikogo.exe
            - mikogo-starter.exe
            - mikogo-service.exe
            - mikogolauncher.exe
            - Mikogo-Service.exe
            - Mikogo-Screen-Service.exe
    selection_image:
        Image|endswith:
            - mikogo.exe
            - mikogo-starter.exe
            - mikogo-service.exe
            - mikogolauncher.exe
            - Mikogo-Service.exe
            - Mikogo-Screen-Service.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Mikogo
level: medium
```
