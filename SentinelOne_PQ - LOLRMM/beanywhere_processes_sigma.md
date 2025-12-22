```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "basuptshelper.exe" or src.process.image.path contains "basupsrvcupdate.exe" or src.process.image.path contains "BASupApp.exe" or src.process.image.path contains "BASupSysInf.exe" or src.process.image.path contains "BASupAppSrvc.exe" or src.process.image.path contains "TakeControl.exe" or src.process.image.path contains "BASupAppElev.exe" or src.process.image.path contains "basupsrvc.exe") or (tgt.process.image.path contains "basuptshelper.exe" or tgt.process.image.path contains "basupsrvcupdate.exe" or tgt.process.image.path contains "BASupApp.exe" or tgt.process.image.path contains "BASupSysInf.exe" or tgt.process.image.path contains "BASupAppSrvc.exe" or tgt.process.image.path contains "TakeControl.exe" or tgt.process.image.path contains "BASupAppElev.exe" or tgt.process.image.path contains "basupsrvc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential BeAnyWhere RMM Tool Process Activity
id: 4838d652-76f6-4171-b998-1943633ffbc3
status: experimental
description: |
    Detects potential processes activity of BeAnyWhere RMM tool
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
            - basuptshelper.exe
            - basupsrvcupdate.exe
            - BASupApp.exe
            - BASupSysInf.exe
            - BASupAppSrvc.exe
            - TakeControl.exe
            - BASupAppElev.exe
            - basupsrvc.exe
    selection_image:
        Image|endswith:
            - basuptshelper.exe
            - basupsrvcupdate.exe
            - BASupApp.exe
            - BASupSysInf.exe
            - BASupAppSrvc.exe
            - TakeControl.exe
            - BASupAppElev.exe
            - basupsrvc.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of BeAnyWhere
level: medium
```
