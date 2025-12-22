```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "konea.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Quest KACE Agent (formerly Dell KACE) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - konea.exe
  condition: selection
id: eda0239d-73f8-4440-98cb-f1fa957e42b4
status: experimental
description: Detects potential processes activity of Quest KACE Agent (formerly Dell
  KACE) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Quest KACE Agent (formerly Dell KACE)
level: medium
```
