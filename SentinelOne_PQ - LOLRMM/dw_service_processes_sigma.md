```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\dwagsvc.exe" or src.process.image.path contains "\\dwagent.exe" or src.process.image.path contains "\\dwaglnc.exe") or (tgt.process.image.path contains "\\dwagsvc.exe" or tgt.process.image.path contains "\\dwagent.exe" or tgt.process.image.path contains "\\dwaglnc.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential DW Service RMM Tool Process Activity
id: 41c78cb0-6366-4b2d-9e34-1caf2811f857
status: experimental
description: |
    Detects potential processes activity of DW Service RMM tool
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
            - '\\dwagsvc.exe'
            - '\\dwagent.exe'
            - '\\dwaglnc.exe'
    selection_image:
        Image|endswith:
            - '\\dwagsvc.exe'
            - '\\dwagent.exe'
            - '\\dwaglnc.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of DW Service
level: medium
```
