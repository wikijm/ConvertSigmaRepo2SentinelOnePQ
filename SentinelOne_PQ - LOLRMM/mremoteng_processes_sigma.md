```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "mRemoteNG.exe" or src.process.image.path contains "mRemoteNG.exe" or src.process.image.path contains "mRemoteNG.exe") or (tgt.process.image.path contains "mRemoteNG.exe" or tgt.process.image.path contains "mRemoteNG.exe" or tgt.process.image.path contains "mRemoteNG.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential mRemoteNG RMM Tool Process Activity
id: 24ca8be4-28b3-40e4-8e95-535710020505
status: experimental
description: |
    Detects potential processes activity of mRemoteNG RMM tool
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
            - mRemoteNG.exe
            - mRemoteNG.exe
            - mRemoteNG.exe
    selection_image:
        Image|endswith:
            - mRemoteNG.exe
            - mRemoteNG.exe
            - mRemoteNG.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of mRemoteNG
level: medium
```
