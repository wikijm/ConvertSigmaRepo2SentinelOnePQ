```sql
// Translated content (automatically translated on 10-11-2025 00:54:40):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\superputty.exe")
```


# Original Sigma Rule:
```yaml
title: Potential SuperPuTTY RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\superputty.exe'
  condition: selection
id: 41eff1f5-a23d-4545-bfd4-97cc71fb51fa
status: experimental
description: Detects potential processes activity of SuperPuTTY RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SuperPuTTY
level: medium
```
