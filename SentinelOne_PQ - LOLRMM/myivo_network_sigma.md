```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "myivo-server.software.informer.com" or event.dns.request contains "myivo-server.software.informer.com"))
```


# Original Sigma Rule:
```yaml
title: Potential MyIVO RMM Tool Network Activity
id: 85f1f9d1-1cf6-4adf-bd87-b0a66390ce4d
status: experimental
description: |
    Detects potential network activity of MyIVO RMM tool
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
        DestinationHostname|endswith: myivo-server.software.informer.com
    condition: selection
falsepositives:
    - Legitimate use of MyIVO
level: medium
```
