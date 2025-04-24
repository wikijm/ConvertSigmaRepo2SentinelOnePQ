```sql
// Translated content (automatically translated on 24-04-2025 01:26:56):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "ltsvc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential LabTeach (Connectwise Automate) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ltsvc.exe
  condition: selection
id: 3696a0f8-c8a0-417a-a408-e9bdf4caf318
status: experimental
description: Detects potential processes activity of LabTeach (Connectwise Automate)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LabTeach (Connectwise Automate)
level: medium
```
