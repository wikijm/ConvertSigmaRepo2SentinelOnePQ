```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "IvantiRemoteControl.exe" or src.process.image.path contains "ArcUI.exe" or src.process.image.path contains "AgentlessRC.exe") or (tgt.process.image.path contains "IvantiRemoteControl.exe" or tgt.process.image.path contains "ArcUI.exe" or tgt.process.image.path contains "AgentlessRC.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Ivanti Remote Control RMM Tool Process Activity
id: ee98c832-56bc-4162-97fd-4963cd37f428
status: experimental
description: |
    Detects potential processes activity of Ivanti Remote Control RMM tool
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
            - IvantiRemoteControl.exe
            - ArcUI.exe
            - AgentlessRC.exe
    selection_image:
        Image|endswith:
            - IvantiRemoteControl.exe
            - ArcUI.exe
            - AgentlessRC.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Ivanti Remote Control
level: medium
```
