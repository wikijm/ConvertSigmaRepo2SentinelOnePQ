```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "n-able.com" or event.dns.request contains "n-able.com"))
```


# Original Sigma Rule:
```yaml
title: Potential N-ABLE Remote Access Software RMM Tool Network Activity
id: f1771336-2160-4937-bea2-fe9f0c18bb87
status: experimental
description: |
    Detects potential network activity of N-ABLE Remote Access Software RMM tool
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
        DestinationHostname|endswith: n-able.com
    condition: selection
falsepositives:
    - Legitimate use of N-ABLE Remote Access Software
level: medium
```
