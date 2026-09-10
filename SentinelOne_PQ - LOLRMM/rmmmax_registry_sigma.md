```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\RMMmax\\AgentService" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RMMmaxAgentService" or registry.keyPath contains "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\RMMmaxAgentService"))
```


# Original Sigma Rule:
```yaml
title: Potential RMMmax RMM Tool Registry Activity
id: 415757cf-925e-5100-ba1f-2ba2ab3ed09d
status: experimental
description: |
    Detects potential registry activity of RMMmax RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-09
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - 'HKLM\SOFTWARE\RMMmax\AgentService'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\RMMmaxAgentService'
            - 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RMMmaxAgentService'
    condition: selection
falsepositives:
    - Legitimate use of RMMmax
level: medium
```
