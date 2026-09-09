```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*\\Teleport Connect Setup-*.exe" or tgt.process.image.path="*\\Teleport Connect Setup-*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Teleport Connect RMM Tool Process Activity
id: 4c8bd4d7-df6b-5390-a389-147dc72caa1e
status: experimental
description: |
    Detects potential processes activity of Teleport Connect RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\\Teleport Connect Setup-*.exe'
    selection_image:
        Image|endswith: '\\Teleport Connect Setup-*.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Teleport Connect
level: medium
```
