```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "bomgar-scc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Bomgar RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - bomgar-scc.exe
  condition: selection
id: 752f62db-1fee-42bd-b5a8-7b4dd3c6e788
status: experimental
description: Detects potential processes activity of Bomgar RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Bomgar
level: medium
```
