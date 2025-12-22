```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "crosstecsoftware.com/remotecontrol") or (event.dns.request contains "user_managed" or event.dns.request contains "crosstecsoftware.com/remotecontrol")))
```


# Original Sigma Rule:
```yaml
title: Potential CrossTec Remote Control RMM Tool Network Activity
id: 91c888e7-1d6d-4cdc-beef-b0c049a647fd
status: experimental
description: |
    Detects potential network activity of CrossTec Remote Control RMM tool
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
            - crosstecsoftware.com/remotecontrol
    condition: selection
falsepositives:
    - Legitimate use of CrossTec Remote Control
level: medium
```
