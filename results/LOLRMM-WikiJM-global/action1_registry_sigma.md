```sql
// Translated content (automatically translated on 30-05-2025 01:37:06):
event.category="Registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\System\CurrentControlSet\Services\A1Agent" or registry.keyPath contains "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe" or registry.keyPath contains "HKLM\SOFTWARE\WOW6432Node\Action1"))
```


# Original Sigma Rule:
```yaml
title: Potential Action1 RMM Tool Registry Activity
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|contains:
    - HKLM\System\CurrentControlSet\Services\A1Agent
    - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe
    - HKLM\SOFTWARE\WOW6432Node\Action1
  condition: selection
id: 178e38f0-33b9-4ff3-a3a5-62cbb073bc45
status: experimental
description: Detects potential registry activity of Action1 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Action1
level: medium
```
