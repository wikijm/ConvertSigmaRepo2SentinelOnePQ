```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "IvantiRemoteControl.exe" or src.process.image.path contains "ArcUI.exe" or src.process.image.path contains "AgentlessRC.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Ivanti Remote Control RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - IvantiRemoteControl.exe
    - ArcUI.exe
    - AgentlessRC.exe
  condition: selection
id: 3036c733-577f-4cc4-ab1c-2d67cc133328
status: experimental
description: Detects potential processes activity of Ivanti Remote Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ivanti Remote Control
level: medium
```
