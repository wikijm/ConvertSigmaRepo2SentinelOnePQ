```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*wisshell*.exe" or src.process.image.path contains "wmc.exe" or src.process.image.path contains "wmc_deployer.exe" or src.process.image.path contains "wmcsvc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RES Automation Manager RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - wisshell*.exe
    - wmc.exe
    - wmc_deployer.exe
    - wmcsvc.exe
  condition: selection
id: 556b34bd-f79f-4227-9d8c-bd628620f472
status: experimental
description: Detects potential processes activity of RES Automation Manager RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RES Automation Manager
level: medium
```
