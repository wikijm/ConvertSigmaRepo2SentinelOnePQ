```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "AgentPackageNetworkDiscovery.exe" or src.process.image.path contains "AgentPackageTaskScheduler.exe" or src.process.image.path contains "AteraAgent.exe" or src.process.image.path contains "atera_agent.exe" or src.process.image.path contains "atera_agent.exe" or src.process.image.path contains "ateraagent.exe" or src.process.image.path contains "syncrosetup.exe") or (tgt.process.image.path contains "AgentPackageNetworkDiscovery.exe" or tgt.process.image.path contains "AgentPackageTaskScheduler.exe" or tgt.process.image.path contains "AteraAgent.exe" or tgt.process.image.path contains "atera_agent.exe" or tgt.process.image.path contains "atera_agent.exe" or tgt.process.image.path contains "ateraagent.exe" or tgt.process.image.path contains "syncrosetup.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Process Activity
id: e151128f-c963-49f4-8899-5d9280d85880
status: experimental
description: |
    Detects potential processes activity of Atera RMM tool
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
            - AgentPackageNetworkDiscovery.exe
            - AgentPackageTaskScheduler.exe
            - AteraAgent.exe
            - atera_agent.exe
            - atera_agent.exe
            - ateraagent.exe
            - syncrosetup.exe
    selection_image:
        Image|endswith:
            - AgentPackageNetworkDiscovery.exe
            - AgentPackageTaskScheduler.exe
            - AteraAgent.exe
            - atera_agent.exe
            - atera_agent.exe
            - ateraagent.exe
            - syncrosetup.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Atera
level: medium
```
