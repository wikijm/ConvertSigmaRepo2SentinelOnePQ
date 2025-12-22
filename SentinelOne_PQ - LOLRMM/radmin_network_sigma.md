```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "radmin.com" or event.dns.request contains "radmin.com"))
```


# Original Sigma Rule:
```yaml
title: Potential RAdmin RMM Tool Network Activity
id: 9a07344a-5d8e-482e-bdf0-2cd3242165e7
status: experimental
description: |
    Detects potential network activity of RAdmin RMM tool
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
        DestinationHostname|endswith: radmin.com
    condition: selection
falsepositives:
    - Legitimate use of RAdmin
level: medium
```
