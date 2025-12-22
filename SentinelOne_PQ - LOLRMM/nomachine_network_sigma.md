```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "nomachine.com") or (event.dns.request contains "user_managed" or event.dns.request contains "nomachine.com")))
```


# Original Sigma Rule:
```yaml
title: Potential NoMachine RMM Tool Network Activity
id: 22d88358-700e-47d3-84df-d7951b17740a
status: experimental
description: |
    Detects potential network activity of NoMachine RMM tool
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
            - user_managed
            - nomachine.com
    condition: selection
falsepositives:
    - Legitimate use of NoMachine
level: medium
```
