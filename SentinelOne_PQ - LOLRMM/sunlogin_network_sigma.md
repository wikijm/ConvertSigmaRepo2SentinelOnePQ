```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "sunlogin.oray.com" or url.address contains "client.oray.net") or (event.dns.request contains "sunlogin.oray.com" or event.dns.request contains "client.oray.net")))
```


# Original Sigma Rule:
```yaml
title: Potential SunLogin RMM Tool Network Activity
id: 3e298919-e799-44b3-8122-35d2b02baa51
status: experimental
description: |
    Detects potential network activity of SunLogin RMM tool
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
            - sunlogin.oray.com
            - client.oray.net
    condition: selection
falsepositives:
    - Legitimate use of SunLogin
level: medium
```
