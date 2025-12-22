```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "rdp.exe" or src.process.image.path="*Pilixo_Installer*.exe") or (tgt.process.image.path contains "rdp.exe" or tgt.process.image.path="*Pilixo_Installer*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Pilixo RMM Tool Process Activity
id: 9c373007-c7ca-443e-a4fd-cc6d77d6f745
status: experimental
description: |
    Detects potential processes activity of Pilixo RMM tool
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
            - rdp.exe
            - Pilixo_Installer*.exe
    selection_image:
        Image|endswith:
            - rdp.exe
            - Pilixo_Installer*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Pilixo
level: medium
```
