```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".my.auvik.com" or url.address contains ".auvik.com" or url.address contains "auvik.com") or (event.dns.request contains ".my.auvik.com" or event.dns.request contains ".auvik.com" or event.dns.request contains "auvik.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Auvik RMM Tool Network Activity
id: 6184c193-a07b-43e8-b72e-6e62b4ec73c9
status: experimental
description: |
    Detects potential network activity of Auvik RMM tool
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
            - '*.my.auvik.com'
            - '*.auvik.com'
            - 'auvik.com'
    condition: selection
falsepositives:
    - Legitimate use of Auvik
level: medium
```
