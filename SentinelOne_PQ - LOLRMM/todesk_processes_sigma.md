```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "todesk.exe" or src.process.image.path contains "ToDesk_Service.exe" or src.process.image.path contains "ToDesk_Setup.exe") or (tgt.process.image.path contains "todesk.exe" or tgt.process.image.path contains "ToDesk_Service.exe" or tgt.process.image.path contains "ToDesk_Setup.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ToDesk RMM Tool Process Activity
id: 4a1e51ee-e208-4281-8977-492e0b98097a
status: experimental
description: |
    Detects potential processes activity of ToDesk RMM tool
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
            - todesk.exe
            - ToDesk_Service.exe
            - ToDesk_Setup.exe
    selection_image:
        Image|endswith:
            - todesk.exe
            - ToDesk_Service.exe
            - ToDesk_Setup.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ToDesk
level: medium
```
