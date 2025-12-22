```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "ehorus standalone.exe")
```


# Original Sigma Rule:
```yaml
title: Potential eHorus RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ehorus standalone.exe
  condition: selection
id: 006d9c2f-3eaf-4b59-b8c3-b9ee5ad5ba47
status: experimental
description: Detects potential processes activity of eHorus RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of eHorus
level: medium
```
