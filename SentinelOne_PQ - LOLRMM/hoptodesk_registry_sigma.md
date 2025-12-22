```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKEY_USERS\*_Classes\\HopToDesk\*")
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Registry Activity
id: 5a643580-395d-4456-87d1-9a6055651987
status: experimental
description: |
    Detects potential registry activity of HopToDesk RMM tool
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
        TargetObject|contains: HKEY_USERS\*_Classes\HopToDesk\*
    condition: selection
falsepositives:
    - Legitimate use of HopToDesk
level: medium
```
