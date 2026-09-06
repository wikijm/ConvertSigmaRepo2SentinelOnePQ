```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".islonline.net" or url.address contains "rmm.barracudamsp.com" or url.address contains "barracudamsp.com") or (event.dns.request contains ".islonline.net" or event.dns.request contains "rmm.barracudamsp.com" or event.dns.request contains "barracudamsp.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Barracuda RMM Tool Network Activity
id: f15d23a0-b1aa-4e74-afe5-4c500848a66d
status: experimental
description: |
    Detects potential network activity of Barracuda RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.islonline.net'
            - 'rmm.barracudamsp.com'
            - 'barracudamsp.com'
    condition: selection
falsepositives:
    - Legitimate use of Barracuda
level: medium
```
