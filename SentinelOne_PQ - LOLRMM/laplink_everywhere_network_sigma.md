```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "everywhere.laplink.com" or url.address contains "le.laplink.com" or url.address contains "atled.syspectr.com") or (event.dns.request contains "everywhere.laplink.com" or event.dns.request contains "le.laplink.com" or event.dns.request contains "atled.syspectr.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Laplink Everywhere RMM Tool Network Activity
id: 4a81a286-94d4-442d-9f11-0977a0c1a80c
status: experimental
description: |
    Detects potential network activity of Laplink Everywhere RMM tool
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
            - everywhere.laplink.com
            - le.laplink.com
            - atled.syspectr.com
    condition: selection
falsepositives:
    - Legitimate use of Laplink Everywhere
level: medium
```
