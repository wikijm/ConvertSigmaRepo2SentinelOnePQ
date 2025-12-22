```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "anyplace-control.com" or event.dns.request contains "anyplace-control.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Anyplace Control RMM Tool Network Activity
id: 6db5caaa-93ad-406b-a8b0-e652033f91a9
status: experimental
description: |
    Detects potential network activity of Anyplace Control RMM tool
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
        DestinationHostname|endswith: anyplace-control.com
    condition: selection
falsepositives:
    - Legitimate use of Anyplace Control
level: medium
```
