```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AlpemixSrvcx")
```


# Original Sigma Rule:
```yaml
title: Potential Alpemix RMM Tool Registry Activity
id: bc21f832-b65a-428e-9692-764f20b24731
status: experimental
description: |
    Detects potential registry activity of Alpemix RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: HKLM\SYSTEM\CurrentControlSet\Services\AlpemixSrvcx
    condition: selection
falsepositives:
    - Legitimate use of Alpemix
level: medium
```
