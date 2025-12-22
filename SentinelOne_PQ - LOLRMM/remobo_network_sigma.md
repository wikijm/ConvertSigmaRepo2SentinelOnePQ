```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "remobo.en.softonic.com") or (event.dns.request contains "user_managed" or event.dns.request contains "remobo.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Remobo RMM Tool Network Activity
id: 346c9a37-5f2b-4fc8-90eb-7a547780a29d
status: experimental
description: |
    Detects potential network activity of Remobo RMM tool
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
        DestinationHostname|endswith:
            - user_managed
            - remobo.en.softonic.com
    condition: selection
falsepositives:
    - Legitimate use of Remobo
level: medium
```
