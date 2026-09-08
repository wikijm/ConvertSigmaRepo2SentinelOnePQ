```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\oolocker.exe" or src.process.image.path contains "\\oosyspectr.exe" or src.process.image.path contains "\\syspectr.exe") or (tgt.process.image.path contains "\\oolocker.exe" or tgt.process.image.path contains "\\oosyspectr.exe" or tgt.process.image.path contains "\\syspectr.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Syspectr RMM Tool Process Activity
id: 791169bf-9cc5-4962-a177-a4dd9d5efd07
status: experimental
description: |
    Detects potential processes activity of Syspectr RMM tool
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
            - '\\oolocker.exe'
            - '\\oosyspectr.exe'
            - '\\syspectr.exe'
    selection_image:
        Image|endswith:
            - '\\oolocker.exe'
            - '\\oosyspectr.exe'
            - '\\syspectr.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Syspectr
level: medium
```
