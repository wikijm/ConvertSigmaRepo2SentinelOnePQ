```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "auth.api.remote.it" or url.address contains "api.remote.it" or url.address contains "remote.it") or (event.dns.request contains "auth.api.remote.it" or event.dns.request contains "api.remote.it" or event.dns.request contains "remote.it")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote.it RMM Tool Network Activity
id: d8ff159e-cd67-4295-9f1a-26db32b2ab06
status: experimental
description: |
    Detects potential network activity of Remote.it RMM tool
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
            - auth.api.remote.it
            - api.remote.it
            - remote.it
    condition: selection
falsepositives:
    - Legitimate use of Remote.it
level: medium
```
