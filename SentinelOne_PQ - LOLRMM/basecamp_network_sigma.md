```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "basecamp.com" or event.dns.request contains "basecamp.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Basecamp RMM Tool Network Activity
id: 890f9d7c-6d30-468e-aee2-2b10c767fff6
status: experimental
description: |
    Detects potential network activity of Basecamp RMM tool
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
        DestinationHostname|endswith: basecamp.com
    condition: selection
falsepositives:
    - Legitimate use of Basecamp
level: medium
```
