```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*pdq-connect*.exe" or tgt.process.image.path="*pdq-connect*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential PDQ Connect RMM Tool Process Activity
id: b78b2eea-dd91-4d3d-8486-9a9cfde212b0
status: experimental
description: |
    Detects potential processes activity of PDQ Connect RMM tool
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
        ParentImage|endswith: pdq-connect*.exe
    selection_image:
        Image|endswith: pdq-connect*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of PDQ Connect
level: medium
```
