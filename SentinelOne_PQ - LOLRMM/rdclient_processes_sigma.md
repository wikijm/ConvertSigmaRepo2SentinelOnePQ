```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\rdclient.exe" or src.process.image.path contains "\\RdClientInstaller.exe" or src.process.image.path contains "\\SupportTool.exe") or (tgt.process.image.path contains "\\rdclient.exe" or tgt.process.image.path contains "\\RdClientInstaller.exe" or tgt.process.image.path contains "\\SupportTool.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RdClient RMM Tool Process Activity
id: 6d9f7f0d-f945-5cc2-aeac-a242f1b1a35c
status: experimental
description: |
    Detects potential processes activity of RdClient RMM tool
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
        ParentImage|endswith:
            - '\\rdclient.exe'
            - '\\RdClientInstaller.exe'
            - '\\SupportTool.exe'
    selection_image:
        Image|endswith:
            - '\\rdclient.exe'
            - '\\RdClientInstaller.exe'
            - '\\SupportTool.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RdClient
level: medium
```
