```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*Sorillus-Launcher*.exe" or src.process.image.path contains "Sorillus Launcher.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Sorillus RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Sorillus-Launcher*.exe
    - Sorillus Launcher.exe
  condition: selection
id: dd380a97-a692-4e46-90cd-aa151b207089
status: experimental
description: Detects potential processes activity of Sorillus RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Sorillus
level: medium
```
