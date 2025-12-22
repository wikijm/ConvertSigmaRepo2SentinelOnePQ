```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ddsystem.exe" or src.process.image.path contains "dd.exe" or src.process.image.path contains "distant-desktop.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Distant Desktop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ddsystem.exe
    - dd.exe
    - distant-desktop.exe
  condition: selection
id: b836c38b-2b26-4464-a575-7ebf486f040f
status: experimental
description: Detects potential processes activity of Distant Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Distant Desktop
level: medium
```
