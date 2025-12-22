```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "tightvnc.com") or (event.dns.request contains "user_managed" or event.dns.request contains "tightvnc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TightVNC RMM Tool Network Activity
id: 73a58ada-ff6a-418b-b559-34f218bd577d
status: experimental
description: |
    Detects potential network activity of TightVNC RMM tool
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
            - tightvnc.com
    condition: selection
falsepositives:
    - Legitimate use of TightVNC
level: medium
```
