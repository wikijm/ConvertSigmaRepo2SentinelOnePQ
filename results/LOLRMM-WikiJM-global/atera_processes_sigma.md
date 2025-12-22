```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\AgentPackageNetworkDiscovery.exe" or src.process.image.path contains "\\AgentPackageTaskScheduler.exe" or src.process.image.path contains "\\AteraAgent.exe" or src.process.image.path contains "atera_agent.exe" or src.process.image.path contains "ateraagent.exe" or src.process.image.path contains "syncrosetup.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\AgentPackageNetworkDiscovery.exe'
    - '*\AgentPackageTaskScheduler.exe'
    - '*\AteraAgent.exe'
    - atera_agent.exe
    - ateraagent.exe
    - syncrosetup.exe
  condition: selection
id: fd34376e-c4cf-4886-8561-57f2a968c8ba
status: experimental
description: Detects potential processes activity of Atera RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Atera
level: medium
```
