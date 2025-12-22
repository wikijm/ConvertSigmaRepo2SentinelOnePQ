```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "rcengmgru.exe" or src.process.image.path contains "rcmgrsvc.exe" or src.process.image.path contains "rxstartsupport.exe" or src.process.image.path contains "rcstartsupport.exe" or src.process.image.path contains "raautoup.exe" or src.process.image.path contains "agentu.exe" or src.process.image.path contains "remotesupportplayeru.exe") or (tgt.process.image.path contains "rcengmgru.exe" or tgt.process.image.path contains "rcmgrsvc.exe" or tgt.process.image.path contains "rxstartsupport.exe" or tgt.process.image.path contains "rcstartsupport.exe" or tgt.process.image.path contains "raautoup.exe" or tgt.process.image.path contains "agentu.exe" or tgt.process.image.path contains "remotesupportplayeru.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RemoteCall RMM Tool Process Activity
id: 04f3918a-9d1e-4c5f-97d5-77b9b02166f3
status: experimental
description: |
    Detects potential processes activity of RemoteCall RMM tool
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
            - rcengmgru.exe
            - rcmgrsvc.exe
            - rxstartsupport.exe
            - rcstartsupport.exe
            - raautoup.exe
            - agentu.exe
            - remotesupportplayeru.exe
    selection_image:
        Image|endswith:
            - rcengmgru.exe
            - rcmgrsvc.exe
            - rxstartsupport.exe
            - rcstartsupport.exe
            - raautoup.exe
            - agentu.exe
            - remotesupportplayeru.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RemoteCall
level: medium
```
