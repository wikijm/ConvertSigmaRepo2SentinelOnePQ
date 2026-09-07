```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKCU\\Software\\99ac595d-36d0-5122-a860-22a3443073cb" or registry.keyPath contains "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\99ac595d-36d0-5122-a860-22a3443073cb"))
```


# Original Sigma Rule:
```yaml
title: Potential RemSupp RMM Tool Registry Activity
id: d5ccdc59-0a3d-54d0-973e-c4b7ffd88f6a
status: experimental
description: |
    Detects potential registry activity of RemSupp RMM tool
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
            - 'HKCU\Software\99ac595d-36d0-5122-a860-22a3443073cb'
            - 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\99ac595d-36d0-5122-a860-22a3443073cb'
    condition: selection
falsepositives:
    - Legitimate use of RemSupp
level: medium
```
