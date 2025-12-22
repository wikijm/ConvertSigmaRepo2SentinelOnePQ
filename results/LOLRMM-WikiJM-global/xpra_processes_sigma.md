```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\Xpra-Launcher.exe" or src.process.image.path contains "\\Xpra-x86_64_Setup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Xpra RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\Xpra-Launcher.exe'
    - '*\Xpra-x86_64_Setup.exe'
  condition: selection
id: 01788429-3310-48f4-852e-6bc26f0747c0
status: experimental
description: Detects potential processes activity of Xpra RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Xpra
level: medium
```
