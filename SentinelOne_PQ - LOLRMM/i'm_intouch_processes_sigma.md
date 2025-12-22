```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "iit.exe" or src.process.image.path contains "intouch.exe" or src.process.image.path contains "I'm InTouch Go Installer.exe") or (tgt.process.image.path contains "iit.exe" or tgt.process.image.path contains "intouch.exe" or tgt.process.image.path contains "I'm InTouch Go Installer.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential I'm InTouch RMM Tool Process Activity
id: 1282f94c-8c40-40b4-9ee9-cdf370d58188
status: experimental
description: |
    Detects potential processes activity of I'm InTouch RMM tool
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
            - iit.exe
            - intouch.exe
            - I'm InTouch Go Installer.exe
    selection_image:
        Image|endswith:
            - iit.exe
            - intouch.exe
            - I'm InTouch Go Installer.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of I'm InTouch
level: medium
```
