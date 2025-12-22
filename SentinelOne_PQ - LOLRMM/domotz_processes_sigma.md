```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "domotz.exe" or src.process.image.path contains "Domotz Pro Desktop App.exe" or src.process.image.path contains "domotz_bash.exe" or src.process.image.path="*domotz*.exe" or src.process.image.path="*Domotz Pro Desktop App Setup*.exe" or src.process.image.path="*domotz-windows*.exe") or (tgt.process.image.path contains "domotz.exe" or tgt.process.image.path contains "Domotz Pro Desktop App.exe" or tgt.process.image.path contains "domotz_bash.exe" or tgt.process.image.path="*domotz*.exe" or tgt.process.image.path="*Domotz Pro Desktop App Setup*.exe" or tgt.process.image.path="*domotz-windows*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Domotz RMM Tool Process Activity
id: cdebd910-7dad-4923-a4db-c40e4ae85d80
status: experimental
description: |
    Detects potential processes activity of Domotz RMM tool
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
            - domotz.exe
            - Domotz Pro Desktop App.exe
            - domotz_bash.exe
            - domotz*.exe
            - Domotz Pro Desktop App Setup*.exe
            - domotz-windows*.exe
    selection_image:
        Image|endswith:
            - domotz.exe
            - Domotz Pro Desktop App.exe
            - domotz_bash.exe
            - domotz*.exe
            - Domotz Pro Desktop App Setup*.exe
            - domotz-windows*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Domotz
level: medium
```
