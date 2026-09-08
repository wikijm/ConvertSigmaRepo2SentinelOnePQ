```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="registry" and (endpoint.os="windows" and registry.keyPath contains "HKLM\\System\\CurrentControlSet\\Services\\LunixarRMM")
```


# Original Sigma Rule:
```yaml
title: Potential Lunixar RMM Tool Registry Activity
id: 4b18c9fa-9200-58cd-be4f-7522bff84c64
status: experimental
description: |
    Detects potential registry activity of Lunixar RMM tool
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
        TargetObject|contains: 'HKLM\System\CurrentControlSet\Services\LunixarRMM'
    condition: selection
falsepositives:
    - Legitimate use of Lunixar
level: medium
```
