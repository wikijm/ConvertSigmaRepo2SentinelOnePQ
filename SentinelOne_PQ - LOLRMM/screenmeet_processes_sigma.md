```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ScreenMeetSupport.exe" or src.process.image.path contains "ScreenMeet.Support.exe") or (tgt.process.image.path contains "ScreenMeetSupport.exe" or tgt.process.image.path contains "ScreenMeet.Support.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenMeet RMM Tool Process Activity
id: 67448f35-4a27-4c04-ab31-3b05d5090b4d
status: experimental
description: |
    Detects potential processes activity of ScreenMeet RMM tool
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
            - ScreenMeetSupport.exe
            - ScreenMeet.Support.exe
    selection_image:
        Image|endswith:
            - ScreenMeetSupport.exe
            - ScreenMeet.Support.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ScreenMeet
level: medium
```
