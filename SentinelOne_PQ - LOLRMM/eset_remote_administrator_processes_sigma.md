```sql
// Translated content (automatically translated on 23-06-2025 00:57:05):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "einstaller.exe" or src.process.image.path contains "era.exe" or src.process.image.path contains "ERAAgent.exe" or src.process.image.path="*ezhelp*.exe" or src.process.image.path contains "eratool.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential ESET Remote Administrator RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - einstaller.exe
    - era.exe
    - ERAAgent.exe
    - ezhelp*.exe
    - eratool.exe
  condition: selection
id: 3963c4a9-9c8f-46c9-999d-cd1859c4312f
status: experimental
description: Detects potential processes activity of ESET Remote Administrator RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ESET Remote Administrator
level: medium
```
