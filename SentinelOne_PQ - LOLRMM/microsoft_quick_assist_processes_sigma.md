```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "quickassist.exe" or tgt.process.image.path contains "quickassist.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft Quick Assist RMM Tool Process Activity
id: 51d6179e-e5f6-4553-b0ae-5df8566b758b
status: experimental
description: |
    Detects potential processes activity of Microsoft Quick Assist RMM tool
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
        ParentImage|endswith: quickassist.exe
    selection_image:
        Image|endswith: quickassist.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Microsoft Quick Assist
level: medium
```
