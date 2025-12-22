```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "ImperoClientSVC.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Impero Connect RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ImperoClientSVC.exe
  condition: selection
id: 271eea29-f7dc-499a-85a6-4907de4cd34a
status: experimental
description: Detects potential processes activity of Impero Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Impero Connect
level: medium
```
