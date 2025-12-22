```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "CagService.exe" or src.process.image.path contains "AEMAgent.exe") or (tgt.process.image.path contains "CagService.exe" or tgt.process.image.path contains "AEMAgent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential CentraStage (Now Datto) RMM Tool Process Activity
id: e0867d17-bfc8-43e2-8607-939676a6b412
status: experimental
description: |
    Detects potential processes activity of CentraStage (Now Datto) RMM tool
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
            - CagService.exe
            - AEMAgent.exe
    selection_image:
        Image|endswith:
            - CagService.exe
            - AEMAgent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of CentraStage (Now Datto)
level: medium
```
