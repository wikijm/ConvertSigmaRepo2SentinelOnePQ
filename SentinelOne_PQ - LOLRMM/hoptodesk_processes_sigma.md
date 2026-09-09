```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\HopToDesk.exe" or src.process.image.path contains "\\HopToDesk-Standalone.exe") or (tgt.process.image.path contains "\\HopToDesk.exe" or tgt.process.image.path contains "\\HopToDesk-Standalone.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Process Activity
id: 74d7f991-3e52-4c08-bb51-85cc7be4b484
status: experimental
description: |
    Detects potential processes activity of HopToDesk RMM tool
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
            - '\\HopToDesk.exe'
            - '\\HopToDesk-Standalone.exe'
    selection_image:
        Image|endswith:
            - '\\HopToDesk.exe'
            - '\\HopToDesk-Standalone.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of HopToDesk
level: medium
```
