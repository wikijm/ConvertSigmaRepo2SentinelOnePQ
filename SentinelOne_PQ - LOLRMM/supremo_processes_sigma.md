```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\supremosystem.exe" or src.process.image.path contains "\\supremo.exe" or src.process.image.path contains "\\supremohelper.exe" or src.process.image.path contains "\\supremoservice.exe") or (tgt.process.image.path contains "\\supremosystem.exe" or tgt.process.image.path contains "\\supremo.exe" or tgt.process.image.path contains "\\supremohelper.exe" or tgt.process.image.path contains "\\supremoservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Supremo RMM Tool Process Activity
id: 59402341-b4b2-4306-b9b5-d49d9c859700
status: experimental
description: |
    Detects potential processes activity of Supremo RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\supremosystem.exe'
            - '\\supremo.exe'
            - '\\supremohelper.exe'
            - '\\supremoservice.exe'
    selection_image:
        Image|endswith:
            - '\\supremosystem.exe'
            - '\\supremo.exe'
            - '\\supremohelper.exe'
            - '\\supremoservice.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Supremo
level: medium
```
