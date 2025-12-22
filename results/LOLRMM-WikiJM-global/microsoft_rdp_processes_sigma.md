```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "mstsc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Microsoft RDP RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - mstsc.exe
  condition: selection
id: 1865354f-ee9f-4e21-a959-490ef6cce164
status: experimental
description: Detects potential processes activity of Microsoft RDP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Microsoft RDP
level: medium
```
