```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ezhelpclientmanager.exe" or src.process.image.path contains "ezHelpManager.exe" or src.process.image.path contains "ezhelpclient.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ezHelp RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ezhelpclientmanager.exe
    - ezHelpManager.exe
    - ezhelpclient.exe
  condition: selection
id: a3d5fca0-c518-4d77-aef3-80aaa4ff00cc
status: experimental
description: Detects potential processes activity of ezHelp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ezHelp
level: medium
```
