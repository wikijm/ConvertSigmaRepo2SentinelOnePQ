```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".action1.com" or url.address contains "a1-backend-packages.s3.amazonaws.com") or (event.dns.request contains ".action1.com" or event.dns.request contains "a1-backend-packages.s3.amazonaws.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Action1 RMM Tool Network Activity
id: 22015403-2881-4c36-ba1b-aff8da000ae6
status: experimental
description: |
    Detects potential network activity of Action1 RMM tool
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
            - '*.action1.com'
            - 'a1-backend-packages.s3.amazonaws.com'
    condition: selection
falsepositives:
    - Legitimate use of Action1
level: medium
```
