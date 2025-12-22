```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "InstallShield Setup.exe" or src.process.image.path contains "ManageEngine_Remote_Access_Plus.exe" or src.process.image.path contains "dcagentservice.exe") or (tgt.process.image.path contains "InstallShield Setup.exe" or tgt.process.image.path contains "ManageEngine_Remote_Access_Plus.exe" or tgt.process.image.path contains "dcagentservice.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ManageEngine RMM Tool Process Activity
id: 0353ecc9-a0d8-4819-8df9-b35f9e766318
status: experimental
description: |
    Detects potential processes activity of ManageEngine RMM tool
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
            - InstallShield Setup.exe
            - ManageEngine_Remote_Access_Plus.exe
            - dcagentservice.exe
    selection_image:
        Image|endswith:
            - InstallShield Setup.exe
            - ManageEngine_Remote_Access_Plus.exe
            - dcagentservice.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ManageEngine
level: medium
```
