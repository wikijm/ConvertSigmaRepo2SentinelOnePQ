```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "rport.io") or (event.dns.request contains "user_managed" or event.dns.request contains "rport.io")))
```


# Original Sigma Rule:
```yaml
title: Potential RPort RMM Tool Network Activity
id: b958832e-79f5-406d-832a-d3da5ea9163a
status: experimental
description: |
    Detects potential network activity of RPort RMM tool
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
            - rport.io
    condition: selection
falsepositives:
    - Legitimate use of RPort
level: medium
```
