```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "search.namequery.com" or url.address contains ".search.namequery.com" or url.address contains "server.absolute.com" or url.address contains ".server.absolute.com") or (event.dns.request contains "search.namequery.com" or event.dns.request contains ".search.namequery.com" or event.dns.request contains "server.absolute.com" or event.dns.request contains ".server.absolute.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Absolute (Computrace) RMM Tool Network Activity
id: 1121ec6d-2ddb-4423-8722-397074293568
status: experimental
description: |
    Detects potential network activity of Absolute (Computrace) RMM tool
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
            - 'search.namequery.com'
            - '*.search.namequery.com'
            - 'server.absolute.com'
            - '*.server.absolute.com'
    condition: selection
falsepositives:
    - Legitimate use of Absolute (Computrace)
level: medium
```
