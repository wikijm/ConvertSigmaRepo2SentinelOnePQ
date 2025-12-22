```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "remotepass-access.exe" or src.process.image.path contains "rpaccess.exe" or src.process.image.path contains "rpwhostscr.exe") or (tgt.process.image.path contains "remotepass-access.exe" or tgt.process.image.path contains "rpaccess.exe" or tgt.process.image.path contains "rpwhostscr.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePass RMM Tool Process Activity
id: 86223db5-ec72-4fbb-8fa6-deca5afb0582
status: experimental
description: |
    Detects potential processes activity of RemotePass RMM tool
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
            - remotepass-access.exe
            - rpaccess.exe
            - rpwhostscr.exe
    selection_image:
        Image|endswith:
            - remotepass-access.exe
            - rpaccess.exe
            - rpwhostscr.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RemotePass
level: medium
```
