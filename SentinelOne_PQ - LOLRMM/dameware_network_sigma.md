```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "dameware.com" or event.dns.request contains "dameware.com"))
```


# Original Sigma Rule:
```yaml
title: Potential DameWare RMM Tool Network Activity
id: 58145224-11b2-4a3e-8d37-1f7769459ece
status: experimental
description: |
    Detects potential network activity of DameWare RMM tool
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
        DestinationHostname|endswith: dameware.com
    condition: selection
falsepositives:
    - Legitimate use of DameWare
level: medium
```
