```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*wisshell*.exe" or src.process.image.path contains "wmc.exe" or src.process.image.path contains "wmc_deployer.exe" or src.process.image.path contains "wmcsvc.exe") or (tgt.process.image.path="*wisshell*.exe" or tgt.process.image.path contains "wmc.exe" or tgt.process.image.path contains "wmc_deployer.exe" or tgt.process.image.path contains "wmcsvc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RES Automation Manager RMM Tool Process Activity
id: ae4d8b43-a9f4-4db1-a54e-dfb30cf6efa5
status: experimental
description: |
    Detects potential processes activity of RES Automation Manager RMM tool
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
            - wisshell*.exe
            - wmc.exe
            - wmc_deployer.exe
            - wmcsvc.exe
    selection_image:
        Image|endswith:
            - wisshell*.exe
            - wmc.exe
            - wmc_deployer.exe
            - wmcsvc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RES Automation Manager
level: medium
```
