```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SOFTWARE\\GoTo Resolve Unattended\\")
```


# Original Sigma Rule:
```yaml
title: Potential GoToAssist (GoTo Resolve) RMM Tool Registry Activity
id: 10da59f2-c2e7-5d83-9a0e-82fbe57008b3
status: experimental
description: |
    Detects potential registry activity of GoToAssist (GoTo Resolve) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: 'HKLM\SOFTWARE\GoTo Resolve Unattended\'
    condition: selection
falsepositives:
    - Legitimate use of GoToAssist (GoTo Resolve)
level: medium
```
