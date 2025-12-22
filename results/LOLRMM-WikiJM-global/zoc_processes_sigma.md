```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\zoc.exe")
```


# Original Sigma Rule:
```yaml
title: Potential ZOC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\zoc.exe'
  condition: selection
id: 6ecbaa7a-6684-4262-9870-058cc85ca350
status: experimental
description: Detects potential processes activity of ZOC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ZOC
level: medium
```
