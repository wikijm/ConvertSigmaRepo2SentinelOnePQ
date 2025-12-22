```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "mwcliun.exe" or src.process.image.path contains "pcnmgr.exe" or src.process.image.path contains "webexpcnow.exe") or (tgt.process.image.path contains "mwcliun.exe" or tgt.process.image.path contains "pcnmgr.exe" or tgt.process.image.path contains "webexpcnow.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Pcnow RMM Tool Process Activity
id: bbb73e66-a04a-4d8c-92bd-7973dd8f33e0
status: experimental
description: |
    Detects potential processes activity of Pcnow RMM tool
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
            - mwcliun.exe
            - pcnmgr.exe
            - webexpcnow.exe
    selection_image:
        Image|endswith:
            - mwcliun.exe
            - pcnmgr.exe
            - webexpcnow.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Pcnow
level: medium
```
