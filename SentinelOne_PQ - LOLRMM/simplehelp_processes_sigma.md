```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "simplehelpcustomer.exe" or src.process.image.path contains "simpleservice.exe" or src.process.image.path contains "simplegatewayservice.exe" or src.process.image.path contains "remote access.exe" or src.process.image.path contains "windowslauncher.exe" or src.process.image.path contains "spsrv.exe") or (tgt.process.image.path contains "simplehelpcustomer.exe" or tgt.process.image.path contains "simpleservice.exe" or tgt.process.image.path contains "simplegatewayservice.exe" or tgt.process.image.path contains "remote access.exe" or tgt.process.image.path contains "windowslauncher.exe" or tgt.process.image.path contains "spsrv.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential SimpleHelp RMM Tool Process Activity
id: 85602ba4-712d-4524-ac2e-7cf7511de816
status: experimental
description: |
    Detects potential processes activity of SimpleHelp RMM tool
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
            - simplehelpcustomer.exe
            - simpleservice.exe
            - simplegatewayservice.exe
            - remote access.exe
            - windowslauncher.exe
            - spsrv.exe
    selection_image:
        Image|endswith:
            - simplehelpcustomer.exe
            - simpleservice.exe
            - simplegatewayservice.exe
            - remote access.exe
            - windowslauncher.exe
            - spsrv.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of SimpleHelp
level: medium
```
