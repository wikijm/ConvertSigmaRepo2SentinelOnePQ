```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "konea.exe" or tgt.process.image.path contains "konea.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Quest KACE Agent (formerly Dell KACE) RMM Tool Process Activity
id: 70edbdd3-5114-47ba-83de-f6b87609473b
status: experimental
description: |
    Detects potential processes activity of Quest KACE Agent (formerly Dell KACE) RMM tool
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
        ParentImage|endswith: konea.exe
    selection_image:
        Image|endswith: konea.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Quest KACE Agent (formerly Dell KACE)
level: medium
```
