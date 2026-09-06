```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".beinsync.net" or url.address contains ".beinsync.com") or (event.dns.request contains ".beinsync.net" or event.dns.request contains ".beinsync.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeInSync RMM Tool Network Activity
id: 815a3008-1333-4d9d-a475-99dab884d493
status: experimental
description: |
    Detects potential network activity of BeInSync RMM tool
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
            - '*.beinsync.net'
            - '*.beinsync.com'
    condition: selection
falsepositives:
    - Legitimate use of BeInSync
level: medium
```
