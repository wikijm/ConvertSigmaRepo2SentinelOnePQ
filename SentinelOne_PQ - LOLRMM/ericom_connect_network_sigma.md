```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ericom.com") or (event.dns.request contains "user_managed" or event.dns.request contains "ericom.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Ericom Connect RMM Tool Network Activity
id: 61428f56-15e4-4f39-8aed-8d2b027024e0
status: experimental
description: |
    Detects potential network activity of Ericom Connect RMM tool
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
            - ericom.com
    condition: selection
falsepositives:
    - Legitimate use of Ericom Connect
level: medium
```
