```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "islonline.com" or event.dns.request contains "islonline.com"))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Light RMM Tool Network Activity
id: 8dbc103e-7cab-4d22-bc9c-c23aa637d88f
status: experimental
description: |
    Detects potential network activity of ISL Light RMM tool
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
        DestinationHostname|endswith: islonline.com
    condition: selection
falsepositives:
    - Legitimate use of ISL Light
level: medium
```
