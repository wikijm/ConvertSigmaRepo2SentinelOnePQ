```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "RDConsole.exe" or src.process.image.path contains "RocketRemoteDesktop_Setup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Rocket Remote Desktop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - RDConsole.exe
    - RocketRemoteDesktop_Setup.exe
  condition: selection
id: ffe2edfb-5ae7-4817-a2c0-644f1e22a5b0
status: experimental
description: Detects potential processes activity of Rocket Remote Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Rocket Remote Desktop
level: medium
```
