```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "basuptshelper.exe" or src.process.image.path contains "basupsrvcupdate.exe" or src.process.image.path contains "BASupApp.exe" or src.process.image.path contains "BASupSysInf.exe" or src.process.image.path contains "BASupAppSrvc.exe" or src.process.image.path contains "TakeControl.exe" or src.process.image.path contains "BASupAppElev.exe" or src.process.image.path contains "basupsrvc.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential BeAnyWhere RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - basuptshelper.exe
    - basupsrvcupdate.exe
    - BASupApp.exe
    - BASupSysInf.exe
    - BASupAppSrvc.exe
    - TakeControl.exe
    - BASupAppElev.exe
    - basupsrvc.exe
  condition: selection
id: 80c4b81e-e606-4715-9834-456c18e5009e
status: experimental
description: Detects potential processes activity of BeAnyWhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeAnyWhere
level: medium
```
