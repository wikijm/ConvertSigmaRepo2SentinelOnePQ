```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\agent-installer-any.exe" or src.process.image.path contains "\\hbrm-x64.exe" or src.process.image.path contains "\\hbrm-updater-x64.exe") or (tgt.process.image.path contains "\\agent-installer-any.exe" or tgt.process.image.path contains "\\hbrm-x64.exe" or tgt.process.image.path contains "\\hbrm-updater-x64.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential HeartbeatRM RMM Tool Process Activity
id: ca4f3aa9-5178-578f-9c94-12231e521d9f
status: experimental
description: |
    Detects potential processes activity of HeartbeatRM RMM tool
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
            - '\\agent-installer-any.exe'
            - '\\hbrm-x64.exe'
            - '\\hbrm-updater-x64.exe'
    selection_image:
        Image|endswith:
            - '\\agent-installer-any.exe'
            - '\\hbrm-x64.exe'
            - '\\hbrm-updater-x64.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of HeartbeatRM
level: medium
```
