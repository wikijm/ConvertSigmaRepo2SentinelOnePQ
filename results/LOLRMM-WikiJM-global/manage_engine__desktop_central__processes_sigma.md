```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "dcagentservice.exe" or src.process.image.path contains "dcagentregister.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Manage Engine (Desktop Central) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - dcagentservice.exe
    - dcagentregister.exe
  condition: selection
id: ff26154b-b874-43f2-8497-5fa6b26f382f
status: experimental
description: Detects potential processes activity of Manage Engine (Desktop Central)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Manage Engine (Desktop Central)
level: medium
```
