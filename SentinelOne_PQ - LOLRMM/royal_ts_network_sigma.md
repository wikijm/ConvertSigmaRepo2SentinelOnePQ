```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "royalapps.com" or event.dns.request contains "royalapps.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Royal TS RMM Tool Network Activity
id: 17763b87-0675-4d9d-95ef-0fb00bb0aa0b
status: experimental
description: |
    Detects potential network activity of Royal TS RMM tool
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
        DestinationHostname|endswith: royalapps.com
    condition: selection
falsepositives:
    - Legitimate use of Royal TS
level: medium
```
