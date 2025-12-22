```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "Kabuto.App.Runner.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Kabuto RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Kabuto.App.Runner.exe
  condition: selection
id: 3322a1a5-e221-49f9-a4bc-53a40519d447
status: experimental
description: Detects potential processes activity of Kabuto RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Kabuto
level: medium
```
