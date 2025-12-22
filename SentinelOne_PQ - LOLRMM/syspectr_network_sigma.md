```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "atled.syspectr.com" or url.address contains "app.syspectr.com") or (event.dns.request contains "atled.syspectr.com" or event.dns.request contains "app.syspectr.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Syspectr RMM Tool Network Activity
id: 7f19fc2c-6952-4582-84c7-70d1e19171f9
status: experimental
description: |
    Detects potential network activity of Syspectr RMM tool
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
            - atled.syspectr.com
            - app.syspectr.com
    condition: selection
falsepositives:
    - Legitimate use of Syspectr
level: medium
```
