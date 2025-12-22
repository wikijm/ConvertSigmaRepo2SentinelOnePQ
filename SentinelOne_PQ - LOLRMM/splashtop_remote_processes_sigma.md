```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "strwinclt.exe" or src.process.image.path="*Splashtop_Streamer_Windows*.exe" or src.process.image.path contains "SplashtopSOS.exe" or src.process.image.path contains "sragent.exe" or src.process.image.path contains "srmanager.exe" or src.process.image.path contains "srserver.exe" or src.process.image.path contains "srservice.exe") or (tgt.process.image.path contains "strwinclt.exe" or tgt.process.image.path="*Splashtop_Streamer_Windows*.exe" or tgt.process.image.path contains "SplashtopSOS.exe" or tgt.process.image.path contains "sragent.exe" or tgt.process.image.path contains "srmanager.exe" or tgt.process.image.path contains "srserver.exe" or tgt.process.image.path contains "srservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop Remote RMM Tool Process Activity
id: 628892d4-70d7-442f-9e46-163b4bd053d8
status: experimental
description: |
    Detects potential processes activity of Splashtop Remote RMM tool
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
            - strwinclt.exe
            - Splashtop_Streamer_Windows*.exe
            - SplashtopSOS.exe
            - sragent.exe
            - srmanager.exe
            - srserver.exe
            - srservice.exe
    selection_image:
        Image|endswith:
            - strwinclt.exe
            - Splashtop_Streamer_Windows*.exe
            - SplashtopSOS.exe
            - sragent.exe
            - srmanager.exe
            - srserver.exe
            - srservice.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Splashtop Remote
level: medium
```
