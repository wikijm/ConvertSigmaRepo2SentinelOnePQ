```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ControlR" or registry.keyPath="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ControlR (*)*"))
```


# Original Sigma Rule:
```yaml
title: Potential ControlR RMM Tool Registry Activity
id: 80a9a9a4-3a35-5915-9d7a-449b162ab7d5
status: experimental
description: |
    Detects potential registry activity of ControlR RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ControlR'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ControlR (*)'
    condition: selection
falsepositives:
    - Legitimate use of ControlR
level: medium
```
