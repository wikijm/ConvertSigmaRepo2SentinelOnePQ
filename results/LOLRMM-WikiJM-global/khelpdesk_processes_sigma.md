```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "KHelpDesk.exe")
```


# Original Sigma Rule:
```yaml
title: Potential KHelpDesk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - KHelpDesk.exe
  condition: selection
id: f202fd9a-3f36-48b5-8902-65e393a61805
status: experimental
description: Detects potential processes activity of KHelpDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of KHelpDesk
level: medium
```
