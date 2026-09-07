```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "zerotier.com" or url.address contains ".zerotier.com") or (event.dns.request contains "zerotier.com" or event.dns.request contains ".zerotier.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ZeroTier RMM Tool Network Activity
id: 13a878f9-2674-401d-9b1b-f2028c440910
status: experimental
description: |
    Detects potential network activity of ZeroTier RMM tool
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
            - 'zerotier.com'
            - '*.zerotier.com'
    condition: selection
falsepositives:
    - Legitimate use of ZeroTier
level: medium
```
