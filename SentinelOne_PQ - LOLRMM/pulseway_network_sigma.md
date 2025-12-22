```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "pulseway.com" or event.dns.request contains "pulseway.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Pulseway RMM Tool Network Activity
id: 7fcd5e3b-db33-4acc-b432-de03c31105b5
status: experimental
description: |
    Detects potential network activity of Pulseway RMM tool
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
        DestinationHostname|endswith: pulseway.com
    condition: selection
falsepositives:
    - Legitimate use of Pulseway
level: medium
```
