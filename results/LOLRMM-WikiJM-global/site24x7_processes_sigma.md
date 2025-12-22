```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "MEAgentHelper.exe" or src.process.image.path contains "MonitoringAgent.exe" or src.process.image.path contains "Site24x7WindowsAgentTrayIcon.exe" or src.process.image.path contains "Site24x7PluginAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Site24x7 RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - MEAgentHelper.exe
    - MonitoringAgent.exe
    - Site24x7WindowsAgentTrayIcon.exe
    - Site24x7PluginAgent.exe
  condition: selection
id: 9d04b875-51f1-4a55-8ce7-56e9a8af5b63
status: experimental
description: Detects potential processes activity of Site24x7 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Site24x7
level: medium
```
