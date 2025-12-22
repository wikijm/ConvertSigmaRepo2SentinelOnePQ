```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\cuteftppro.exe")
```


# Original Sigma Rule:
```yaml
title: Potential CuteFTP RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\cuteftppro.exe'
  condition: selection
id: 83e2b32c-24fd-4f57-a3a2-807e4ff592d2
status: experimental
description: Detects potential processes activity of CuteFTP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CuteFTP
level: medium
```
