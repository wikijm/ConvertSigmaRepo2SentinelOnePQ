```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "OTService.exe" or src.process.image.path contains "OTPowerShell.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential OptiTune RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - OTService.exe
    - OTPowerShell.exe
  condition: selection
id: 6f92accd-69ed-4cea-a134-e55bb58f496a
status: experimental
description: Detects potential processes activity of OptiTune RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of OptiTune
level: medium
```
