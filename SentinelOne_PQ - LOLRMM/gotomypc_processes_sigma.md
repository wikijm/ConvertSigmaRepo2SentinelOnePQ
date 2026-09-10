```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\G2M.exe" or tgt.process.image.path contains "\\G2M.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential GoToMyPC RMM Tool Process Activity
id: c4c9f5cc-740d-51ef-bea5-af3a9f0c13eb
status: experimental
description: |
    Detects potential processes activity of GoToMyPC RMM tool
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
        ParentImage|endswith: '\\G2M.exe'
    selection_image:
        Image|endswith: '\\G2M.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of GoToMyPC
level: medium
```
