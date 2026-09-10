```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\tinClientSessionManager-" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\tinClientSessionManager-"))
```


# Original Sigma Rule:
```yaml
title: Potential SetMe PRO RMM Tool Registry Activity
id: 75a72020-5ab2-554b-b81a-384b81f44940
status: experimental
description: |
    Detects potential registry activity of SetMe PRO RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-02
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
            - 'HKLM\SYSTEM\CurrentControlSet\Services\tinClientSessionManager-*'
            - 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\tinClientSessionManager-*'
    condition: selection
falsepositives:
    - Legitimate use of SetMe PRO
level: medium
```
