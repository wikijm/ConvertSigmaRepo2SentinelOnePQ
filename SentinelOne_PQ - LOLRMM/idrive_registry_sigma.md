```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKEY_LOCAL_MACHINE\\SOFTWARE\\IDrive\*" or registry.keyPath contains "HKEY_CURRENT_USER\\SOFTWARE\\IDrive\*"))
```


# Original Sigma Rule:
```yaml
title: Potential iDrive RMM Tool Registry Activity
id: 1192dc81-6a33-50b7-bb18-18b8f1034001
status: experimental
description: |
    Detects potential registry activity of iDrive RMM tool
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
            - 'HKEY_LOCAL_MACHINE\SOFTWARE\IDrive\*'
            - 'HKEY_CURRENT_USER\SOFTWARE\IDrive\*'
    condition: selection
falsepositives:
    - Legitimate use of iDrive
level: medium
```
