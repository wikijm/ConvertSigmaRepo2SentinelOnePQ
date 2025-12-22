```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "BASupSrvc.exe" or src.process.image.path contains "winagent.exe" or src.process.image.path contains "BASupApp.exe" or src.process.image.path contains "BASupTSHelper.exe" or src.process.image.path="*Agent_*_RW.exe" or src.process.image.path contains "BASEClient.exe" or src.process.image.path contains "BASupSrvcCnfg.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential N-Able Advanced Monitoring Agent RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - BASupSrvc.exe
    - winagent.exe
    - BASupApp.exe
    - BASupTSHelper.exe
    - Agent_*_RW.exe
    - BASEClient.exe
    - BASupSrvcCnfg.exe
  condition: selection
id: e5bd2958-99d7-4d10-99cc-56d3e2ec3d56
status: experimental
description: Detects potential processes activity of N-Able Advanced Monitoring Agent
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of N-Able Advanced Monitoring Agent
level: medium
```
