```sql
// Translated content (automatically translated on 02-06-2025 00:55:03):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "dcagentservice.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Desktop Central RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - dcagentservice.exe
  condition: selection
id: 239e8a76-aee7-4840-9428-ecfe26be8103
status: experimental
description: Detects potential processes activity of Desktop Central RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Desktop Central
level: medium
```
