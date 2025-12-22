```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ehorus standalone.exe" or src.process.image.path contains "ehorus_agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pandora RC (eHorus) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ehorus standalone.exe
    - ehorus_agent.exe
  condition: selection
id: 0a18fcba-4d6d-4a78-9e5a-81294907bc16
status: experimental
description: Detects potential processes activity of Pandora RC (eHorus) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pandora RC (eHorus)
level: medium
```
