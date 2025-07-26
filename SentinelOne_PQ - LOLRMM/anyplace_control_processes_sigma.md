```sql
// Translated content (automatically translated on 26-07-2025 00:55:02):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "apc_host.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Anyplace Control RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - apc_host.exe
  condition: selection
id: b8b70d3d-58df-4a20-b4c0-e225f291f230
status: experimental
description: Detects potential processes activity of Anyplace Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Anyplace Control
level: medium
```
