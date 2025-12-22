```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\WinSCP.exe")
```


# Original Sigma Rule:
```yaml
title: Potential WinSCP RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\WinSCP.exe'
  condition: selection
id: efbd211f-a10d-499c-b395-cc60cc49ba3e
status: experimental
description: Detects potential processes activity of WinSCP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of WinSCP
level: medium
```
