```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "level-windows-amd64.exe" or src.process.image.path contains "level.exe" or src.process.image.path contains "level-remote-control-ffmpeg.exe") or (tgt.process.image.path contains "level-windows-amd64.exe" or tgt.process.image.path contains "level.exe" or tgt.process.image.path contains "level-remote-control-ffmpeg.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Level.io RMM Tool Process Activity
id: 7b0dc14e-d5e7-4b30-91f0-92a1ce61619c
status: experimental
description: |
    Detects potential processes activity of Level.io RMM tool
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
            - level-windows-amd64.exe
            - level.exe
            - level-remote-control-ffmpeg.exe
    selection_image:
        Image|endswith:
            - level-windows-amd64.exe
            - level.exe
            - level-remote-control-ffmpeg.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Level.io
level: medium
```
