```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "CagService.exe" or src.process.image.path contains "AEMAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential CentraStage (Now Datto) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - CagService.exe
    - AEMAgent.exe
  condition: selection
id: a71f32fd-3e47-4d97-ac70-af5d7d9ded37
status: experimental
description: Detects potential processes activity of CentraStage (Now Datto) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CentraStage (Now Datto)
level: medium
```
