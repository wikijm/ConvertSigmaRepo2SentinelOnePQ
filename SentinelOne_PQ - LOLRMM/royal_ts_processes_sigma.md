```sql
// Translated content (automatically translated on 01-05-2025 01:43:46):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "royalts.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Royal TS RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - royalts.exe
  condition: selection
id: 5a1504da-daca-4287-995f-3b911f517848
status: experimental
description: Detects potential processes activity of Royal TS RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Royal TS
level: medium
```
