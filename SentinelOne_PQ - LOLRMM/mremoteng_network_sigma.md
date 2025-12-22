```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "mremoteng.org") or (event.dns.request contains "user_managed" or event.dns.request contains "mremoteng.org")))
```


# Original Sigma Rule:
```yaml
title: Potential mRemoteNG RMM Tool Network Activity
id: c7ae64c2-1850-4c69-8831-ca9221bb0165
status: experimental
description: |
    Detects potential network activity of mRemoteNG RMM tool
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
            - mremoteng.org
    condition: selection
falsepositives:
    - Legitimate use of mRemoteNG
level: medium
```
