```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\SharpChisel.exe" or tgt.process.displayName="SharpChisel"))
```


# Original Sigma Rule:
```yaml
title: HackTool - SharpChisel Execution
id: cf93e05e-d798-4d9e-b522-b0248dc61eaf
related:
    - id: 8b0e12da-d3c3-49db-bb4f-256703f380e5
      type: similar
status: test
description: Detects usage of the Sharp Chisel via the commandline arguments
references:
    - https://github.com/shantanu561993/SharpChisel
    - https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-05
modified: 2023-02-13
tags:
    - attack.command-and-control
    - attack.t1090.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpChisel.exe'
        - Product: 'SharpChisel'
    # See rule 8b0e12da-d3c3-49db-bb4f-256703f380e5 for Chisel.exe coverage
    condition: selection
falsepositives:
    - Unlikely
level: high
```
