```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "NTRsupportPro_EN.exe" or tgt.process.image.path contains "NTRsupportPro_EN.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential NTR Remote RMM Tool Process Activity
id: 44ec1ea4-7d35-4aee-a5a2-65f78442aacd
status: experimental
description: |
    Detects potential processes activity of NTR Remote RMM tool
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
        ParentImage|endswith: NTRsupportPro_EN.exe
    selection_image:
        Image|endswith: NTRsupportPro_EN.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of NTR Remote
level: medium
```
