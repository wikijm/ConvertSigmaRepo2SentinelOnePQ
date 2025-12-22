```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "rport.exe")
```


# Original Sigma Rule:
```yaml
title: Potential RPort RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rport.exe
  condition: selection
id: 0a914737-0a66-4bfb-98f4-4f6e46c25f86
status: experimental
description: Detects potential processes activity of RPort RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RPort
level: medium
```
