```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TrustConnect Agent" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TrustConnect Agent" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\TrustConnectAgent_" or registry.keyPath contains "HKLM\\SOFTWARE\\Classes\\AppID\\TrustConnectAgent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential TrustConnect RMM Tool Registry Activity
id: 71d7cef9-71d4-5899-a2d7-060f639bb807
status: experimental
description: |
    Detects potential registry activity of TrustConnect RMM tool
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
        TargetObject|contains:
            - 'HKLM\SYSTEM\CurrentControlSet\Services\TrustConnect Agent'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TrustConnect Agent'
            - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TrustConnectAgent_*'
            - 'HKLM\SOFTWARE\Classes\AppID\TrustConnectAgent.exe'
    condition: selection
falsepositives:
    - Legitimate use of TrustConnect
level: medium
```
