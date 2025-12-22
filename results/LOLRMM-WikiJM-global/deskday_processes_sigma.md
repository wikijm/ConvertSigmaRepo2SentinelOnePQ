```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*ultimate_*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential DeskDay RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ultimate_*.exe
  condition: selection
id: 0cb80515-5804-40eb-9491-74381eb04a36
status: experimental
description: Detects potential processes activity of DeskDay RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DeskDay
level: medium
```
