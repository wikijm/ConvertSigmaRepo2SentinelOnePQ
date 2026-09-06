```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\ehorus standalone.exe" or src.process.image.path contains "\\ehorus_agent.exe" or src.process.image.path contains "\\ehorus_cmd.exe" or src.process.image.path contains "\\ehorus_launcher.exe" or src.process.image.path contains "\\ehorus_uit.exe") or (tgt.process.image.path contains "\\ehorus standalone.exe" or tgt.process.image.path contains "\\ehorus_agent.exe" or tgt.process.image.path contains "\\ehorus_cmd.exe" or tgt.process.image.path contains "\\ehorus_launcher.exe" or tgt.process.image.path contains "\\ehorus_uit.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential eHorus RMM Tool Process Activity
id: 740d017e-89db-4f2e-9cbe-74e08503bb76
status: experimental
description: |
    Detects potential processes activity of eHorus RMM tool
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
            - '\\ehorus standalone.exe'
            - '\\ehorus_agent.exe'
            - '\\ehorus_cmd.exe'
            - '\\ehorus_launcher.exe'
            - '\\ehorus_uit.exe'
    selection_image:
        Image|endswith:
            - '\\ehorus standalone.exe'
            - '\\ehorus_agent.exe'
            - '\\ehorus_cmd.exe'
            - '\\ehorus_launcher.exe'
            - '\\ehorus_uit.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of eHorus
level: medium
```
