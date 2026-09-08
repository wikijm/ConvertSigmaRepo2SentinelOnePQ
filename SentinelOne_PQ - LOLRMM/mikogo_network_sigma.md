```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".real-time-collaboration.com" or url.address contains ".mikogo4.com" or url.address contains ".mikogo.com" or url.address contains "mikogo.com") or (event.dns.request contains ".real-time-collaboration.com" or event.dns.request contains ".mikogo4.com" or event.dns.request contains ".mikogo.com" or event.dns.request contains "mikogo.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Mikogo RMM Tool Network Activity
id: 8a8e4fac-2c46-4833-b0ef-aa845317ffc6
status: experimental
description: |
    Detects potential network activity of Mikogo RMM tool
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
            - '*.real-time-collaboration.com'
            - '*.mikogo4.com'
            - '*.mikogo.com'
            - 'mikogo.com'
    condition: selection
falsepositives:
    - Legitimate use of Mikogo
level: medium
```
