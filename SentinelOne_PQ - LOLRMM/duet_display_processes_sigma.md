```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\duet.exe" or src.process.image.path contains "\\DuetSetup.exe" or src.process.image.path contains "\\DuetDisp.exe") or (tgt.process.image.path contains "\\duet.exe" or tgt.process.image.path contains "\\DuetSetup.exe" or tgt.process.image.path contains "\\DuetDisp.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Duet Display RMM Tool Process Activity
id: e9133ac9-398c-5a2a-9a97-1b0006fcfe10
status: experimental
description: |
    Detects potential processes activity of Duet Display RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '\\duet.exe'
            - '\\DuetSetup.exe'
            - '\\DuetDisp.exe'
    selection_image:
        Image|endswith:
            - '\\duet.exe'
            - '\\DuetSetup.exe'
            - '\\DuetDisp.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Duet Display
level: medium
```
