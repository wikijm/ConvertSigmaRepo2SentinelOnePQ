```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\NinjaRMMAgent.exe" or src.process.image.path contains "\\NinjaRMMAgentPatcher.exe" or src.process.image.path contains "\\ninjarmm-cli.exe") or (tgt.process.image.path contains "\\NinjaRMMAgent.exe" or tgt.process.image.path contains "\\NinjaRMMAgentPatcher.exe" or tgt.process.image.path contains "\\ninjarmm-cli.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential NinjaRMM RMM Tool Process Activity
id: 75028b26-78a3-4dc3-acc1-f8b6d8ae5fc9
status: experimental
description: |
    Detects potential processes activity of NinjaRMM RMM tool
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
            - '\\NinjaRMMAgent.exe'
            - '\\NinjaRMMAgentPatcher.exe'
            - '\\ninjarmm-cli.exe'
    selection_image:
        Image|endswith:
            - '\\NinjaRMMAgent.exe'
            - '\\NinjaRMMAgentPatcher.exe'
            - '\\ninjarmm-cli.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of NinjaRMM
level: medium
```
