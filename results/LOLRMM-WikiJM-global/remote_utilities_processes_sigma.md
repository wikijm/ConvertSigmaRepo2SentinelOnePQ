```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rutview.exe" or src.process.image.path contains "rutserv.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Utilities RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rutview.exe
    - rutserv.exe
  condition: selection
id: 25341a7d-f001-4a8b-89ae-dec90cbe3817
status: experimental
description: Detects potential processes activity of Remote Utilities RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote Utilities
level: medium
```
