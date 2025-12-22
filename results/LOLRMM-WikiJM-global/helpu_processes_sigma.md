```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "helpu_install.exe" or src.process.image.path contains "HelpuUpdater.exe" or src.process.image.path contains "HelpuManager.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential HelpU RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - helpu_install.exe
    - HelpuUpdater.exe
    - HelpuManager.exe
  condition: selection
id: 0779ec5e-05d7-4174-ab1c-a66175b3bf92
status: experimental
description: Detects potential processes activity of HelpU RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of HelpU
level: medium
```
