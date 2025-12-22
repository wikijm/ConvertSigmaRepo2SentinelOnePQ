```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path="*meshcentral*.exe" or src.process.image.path="*meshagent*.exe") or (tgt.process.image.path="*meshcentral*.exe" or tgt.process.image.path="*meshagent*.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential MeshCentral RMM Tool Process Activity
id: 14c902eb-2fb2-4fa9-a2da-adbd83861c1c
status: experimental
description: |
    Detects potential processes activity of MeshCentral RMM tool
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
            - meshcentral*.exe
            - meshagent*.exe
    selection_image:
        Image|endswith:
            - meshcentral*.exe
            - meshagent*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of MeshCentral
level: medium
```
