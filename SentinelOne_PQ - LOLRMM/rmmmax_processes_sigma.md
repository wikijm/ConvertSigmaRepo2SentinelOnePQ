```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\RMMmaxAgentSetup.exe" or src.process.image.path contains "\\RMMmaxAgentService.exe") or (tgt.process.image.path contains "\\RMMmaxAgentSetup.exe" or tgt.process.image.path contains "\\RMMmaxAgentService.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RMMmax RMM Tool Process Activity
id: b34fad1f-e54d-5b86-9160-b726ac2bc32d
status: experimental
description: |
    Detects potential processes activity of RMMmax RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-09
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\RMMmaxAgentSetup.exe'
            - '\\RMMmaxAgentService.exe'
    selection_image:
        Image|endswith:
            - '\\RMMmaxAgentSetup.exe'
            - '\\RMMmaxAgentService.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RMMmax
level: medium
```
