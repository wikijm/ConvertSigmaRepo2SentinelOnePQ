```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "signal.hoptodesk.com" or url.address contains "api.hoptodesk.com" or url.address contains "turn.hoptodesk.com") or (event.dns.request contains "signal.hoptodesk.com" or event.dns.request contains "api.hoptodesk.com" or event.dns.request contains "turn.hoptodesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Network Activity
id: 68fd1e88-4536-42ee-8517-cd8fbc3df925
status: experimental
description: |
    Detects potential network activity of HopToDesk RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - signal.hoptodesk.com
            - api.hoptodesk.com
            - turn.hoptodesk.com
    condition: selection
falsepositives:
    - Legitimate use of HopToDesk
level: medium
```
