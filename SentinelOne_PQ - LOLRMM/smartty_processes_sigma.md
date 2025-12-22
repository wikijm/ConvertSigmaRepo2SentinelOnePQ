```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "SmarTTY.exe" or tgt.process.image.path contains "SmarTTY.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential SmarTTY RMM Tool Process Activity
id: b3993d3e-9624-4d2d-aafd-a3df18b3aedc
status: experimental
description: |
    Detects potential processes activity of SmarTTY RMM tool
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
        ParentImage|endswith: SmarTTY.exe
    selection_image:
        Image|endswith: SmarTTY.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of SmarTTY
level: medium
```
