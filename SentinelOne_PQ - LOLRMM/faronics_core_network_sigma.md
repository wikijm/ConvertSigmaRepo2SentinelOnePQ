```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "upd.faronicslabs.com" or url.address contains "faronics.com" or url.address contains "www.faronics.com" or url.address contains "user_managed") or (event.dns.request contains "upd.faronicslabs.com" or event.dns.request contains "faronics.com" or event.dns.request contains "www.faronics.com" or event.dns.request contains "user_managed")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Core RMM Tool Network Activity
id: 8d92ab1f-52f3-5e8c-98bb-21c160a3577f
status: experimental
description: |
    Detects potential network activity of Faronics Core RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - 'upd.faronicslabs.com'
            - 'faronics.com'
            - 'www.faronics.com'
            - 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of Faronics Core
level: medium
```
