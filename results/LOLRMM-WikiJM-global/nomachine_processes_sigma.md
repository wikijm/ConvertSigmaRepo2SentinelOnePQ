```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*nomachine*.exe" or src.process.image.path contains "nxd.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential NoMachine RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - nomachine*.exe
    - nxd.exe
  condition: selection
id: 40a4638d-dc15-40f9-be1f-f5667b56a562
status: experimental
description: Detects potential processes activity of NoMachine RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NoMachine
level: medium
```
