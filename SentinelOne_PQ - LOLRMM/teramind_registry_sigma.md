```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\tsvchst" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\tsvchst\\ImagePath" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\tsvchst\\Start"))
```


# Original Sigma Rule:
```yaml
title: Potential Teramind RMM Tool Registry Activity
id: 41f5cfa2-adec-5553-ac55-5a1526880875
status: experimental
description: |
    Detects potential registry activity of Teramind RMM tool
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
            - 'HKLM\SYSTEM\CurrentControlSet\Services\tsvchst'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\tsvchst\ImagePath'
            - 'HKLM\SYSTEM\CurrentControlSet\Services\tsvchst\Start'
    condition: selection
falsepositives:
    - Legitimate use of Teramind
level: medium
```
