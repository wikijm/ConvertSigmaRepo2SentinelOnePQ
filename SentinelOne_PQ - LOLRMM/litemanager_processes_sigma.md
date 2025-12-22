```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "lmnoipserver.exe" or src.process.image.path contains "ROMFUSClient.exe" or src.process.image.path contains "romfusclient.exe" or src.process.image.path contains "romviewer.exe" or src.process.image.path contains "romserver.exe" or src.process.image.path contains "ROMServer.exe") or (tgt.process.image.path contains "lmnoipserver.exe" or tgt.process.image.path contains "ROMFUSClient.exe" or tgt.process.image.path contains "romfusclient.exe" or tgt.process.image.path contains "romviewer.exe" or tgt.process.image.path contains "romserver.exe" or tgt.process.image.path contains "ROMServer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential LiteManager RMM Tool Process Activity
id: acfaf9ef-6248-4d0d-94f4-c5e78395fb9c
status: experimental
description: |
    Detects potential processes activity of LiteManager RMM tool
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
            - lmnoipserver.exe
            - ROMFUSClient.exe
            - romfusclient.exe
            - romviewer.exe
            - romserver.exe
            - ROMServer.exe
    selection_image:
        Image|endswith:
            - lmnoipserver.exe
            - ROMFUSClient.exe
            - romfusclient.exe
            - romviewer.exe
            - romserver.exe
            - ROMServer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of LiteManager
level: medium
```
