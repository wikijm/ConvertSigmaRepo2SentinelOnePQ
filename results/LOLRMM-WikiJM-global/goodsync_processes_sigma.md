```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "GoodSync-vsub-Setup.exe")
```


# Original Sigma Rule:
```yaml
title: Potential GoodSync RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - GoodSync-vsub-Setup.exe
  condition: selection
id: 1de89b25-4e7d-4020-bf52-f51e1a22e38f
status: experimental
description: Detects potential processes activity of GoodSync RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GoodSync
level: medium
```
