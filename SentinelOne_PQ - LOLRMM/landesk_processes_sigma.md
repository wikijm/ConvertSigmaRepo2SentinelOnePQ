```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "issuser.exe" or src.process.image.path contains "landeskagentbootstrap.exe" or src.process.image.path contains "LANDeskPortalManager.exe" or src.process.image.path contains "ldinv32.exe" or src.process.image.path contains "ldsensors.exe" or src.process.image.path contains "issuser.exe" or src.process.image.path contains "softmon.exe" or src.process.image.path contains "tmcsvc.exe") or (tgt.process.image.path contains "issuser.exe" or tgt.process.image.path contains "landeskagentbootstrap.exe" or tgt.process.image.path contains "LANDeskPortalManager.exe" or tgt.process.image.path contains "ldinv32.exe" or tgt.process.image.path contains "ldsensors.exe" or tgt.process.image.path contains "issuser.exe" or tgt.process.image.path contains "softmon.exe" or tgt.process.image.path contains "tmcsvc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential LANDesk RMM Tool Process Activity
id: ee604e54-ca2b-4b4c-a6c8-1136da7601ce
status: experimental
description: |
    Detects potential processes activity of LANDesk RMM tool
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
            - issuser.exe
            - landeskagentbootstrap.exe
            - LANDeskPortalManager.exe
            - ldinv32.exe
            - ldsensors.exe
            - issuser.exe
            - softmon.exe
            - tmcsvc.exe
    selection_image:
        Image|endswith:
            - issuser.exe
            - landeskagentbootstrap.exe
            - LANDeskPortalManager.exe
            - ldinv32.exe
            - ldsensors.exe
            - issuser.exe
            - softmon.exe
            - tmcsvc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of LANDesk
level: medium
```
