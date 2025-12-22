```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "deskday.ai" or url.address contains "app.deskday.ai") or (event.dns.request contains "deskday.ai" or event.dns.request contains "app.deskday.ai")))
```


# Original Sigma Rule:
```yaml
title: Potential DeskDay RMM Tool Network Activity
id: d4cfe618-7477-44c2-a9b1-34e0add888fe
status: experimental
description: |
    Detects potential network activity of DeskDay RMM tool
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
            - deskday.ai
            - app.deskday.ai
    condition: selection
falsepositives:
    - Legitimate use of DeskDay
level: medium
```
