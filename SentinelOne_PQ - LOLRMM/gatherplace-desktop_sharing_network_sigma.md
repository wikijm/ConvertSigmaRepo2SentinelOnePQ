```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".gatherplace.com" or url.address contains ".gatherplace.net" or url.address contains "gatherplace.com") or (event.dns.request contains ".gatherplace.com" or event.dns.request contains ".gatherplace.net" or event.dns.request contains "gatherplace.com")))
```


# Original Sigma Rule:
```yaml
title: Potential GatherPlace-desktop sharing RMM Tool Network Activity
id: bd0dc445-6398-43ee-9543-552b68f0ec72
status: experimental
description: |
    Detects potential network activity of GatherPlace-desktop sharing RMM tool
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
            - '*.gatherplace.com'
            - '*.gatherplace.net'
            - 'gatherplace.com'
    condition: selection
falsepositives:
    - Legitimate use of GatherPlace-desktop sharing
level: medium
```
