```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "MEAgentHelper.exe" or src.process.image.path contains "MonitoringAgent.exe" or src.process.image.path contains "Site24x7WindowsAgentTrayIcon.exe" or src.process.image.path contains "Site24x7PluginAgent.exe") or (tgt.process.image.path contains "MEAgentHelper.exe" or tgt.process.image.path contains "MonitoringAgent.exe" or tgt.process.image.path contains "Site24x7WindowsAgentTrayIcon.exe" or tgt.process.image.path contains "Site24x7PluginAgent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Site24x7 RMM Tool Process Activity
id: 8ad21b7a-7b49-4680-8547-ba306fed6bc6
status: experimental
description: |
    Detects potential processes activity of Site24x7 RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - MEAgentHelper.exe
            - MonitoringAgent.exe
            - Site24x7WindowsAgentTrayIcon.exe
            - Site24x7PluginAgent.exe
    selection_image:
        Image|endswith:
            - MEAgentHelper.exe
            - MonitoringAgent.exe
            - Site24x7WindowsAgentTrayIcon.exe
            - Site24x7PluginAgent.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Site24x7
level: medium
```
