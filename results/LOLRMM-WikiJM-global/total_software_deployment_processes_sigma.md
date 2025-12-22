```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\tniwinagent.exe" or src.process.image.path contains "\\Tsdservice.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Total Software Deployment RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\tniwinagent.exe'
    - '*\Tsdservice.exe'
  condition: selection
id: 3d985eb7-b4be-432b-be5c-7fe376d06b40
status: experimental
description: Detects potential processes activity of Total Software Deployment RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Total Software Deployment
level: medium
```
