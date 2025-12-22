```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "xeox-agent_x64.exe" or src.process.image.path contains "xeox_service_windows.exe" or src.process.image.path="*xeox-agent_*.exe" or src.process.image.path contains "xeox-agent_x86.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Xeox RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - xeox-agent_x64.exe
    - xeox_service_windows.exe
    - xeox-agent_*.exe
    - xeox-agent_x86.exe
  condition: selection
id: 9063ed28-7fb7-4ea6-af24-e51e6d0cbb09
status: experimental
description: Detects potential processes activity of Xeox RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Xeox
level: medium
```
