```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\hsloader.exe" or src.process.image.path contains "\\InstantHousecall.exe" or src.process.image.path contains "\\ihcserver.exe") or (tgt.process.image.path contains "\\hsloader.exe" or tgt.process.image.path contains "\\InstantHousecall.exe" or tgt.process.image.path contains "\\ihcserver.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Instant Housecall RMM Tool Process Activity
id: d1610f9a-a13c-4033-80f5-695b87d8506c
status: experimental
description: |
    Detects potential processes activity of Instant Housecall RMM tool
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
            - '\\hsloader.exe'
            - '\\InstantHousecall.exe'
            - '\\ihcserver.exe'
    selection_image:
        Image|endswith:
            - '\\hsloader.exe'
            - '\\InstantHousecall.exe'
            - '\\ihcserver.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Instant Housecall
level: medium
```
