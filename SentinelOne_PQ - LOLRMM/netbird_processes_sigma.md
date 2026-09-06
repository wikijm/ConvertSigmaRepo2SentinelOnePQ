```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\netbird.exe" or src.process.image.path contains "\\netbird-ui.exe") or (tgt.process.image.path contains "\\netbird.exe" or tgt.process.image.path contains "\\netbird-ui.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential NetBird RMM Tool Process Activity
id: 48b0db99-b021-5bd7-9a73-7a2733099102
status: experimental
description: |
    Detects potential processes activity of NetBird RMM tool
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
            - '\\netbird.exe'
            - '\\netbird-ui.exe'
    selection_image:
        Image|endswith:
            - '\\netbird.exe'
            - '\\netbird-ui.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of NetBird
level: medium
```
