```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\Policies\\Teleport\\TeleportConnect" or registry.keyPath contains "HKCU\\SOFTWARE\\Policies\\Teleport\\TeleportConnect"))
```


# Original Sigma Rule:
```yaml
title: Potential Teleport Connect RMM Tool Registry Activity
id: 950e3967-4474-569c-8908-1558060485f3
status: experimental
description: |
    Detects potential registry activity of Teleport Connect RMM tool
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
            - 'HKLM\SOFTWARE\Policies\Teleport\TeleportConnect'
            - 'HKCU\SOFTWARE\Policies\Teleport\TeleportConnect'
    condition: selection
falsepositives:
    - Legitimate use of Teleport Connect
level: medium
```
