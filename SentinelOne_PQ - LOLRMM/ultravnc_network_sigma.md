```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "ultravnc.com" or url.address contains "user_managed") or (event.dns.request contains "ultravnc.com" or event.dns.request contains "user_managed")))
```


# Original Sigma Rule:
```yaml
title: Potential UltraVNC RMM Tool Network Activity
id: c607606c-d7ad-4954-835e-eb32122885fb
status: experimental
description: |
    Detects potential network activity of UltraVNC RMM tool
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
            - ultravnc.com
            - user_managed
    condition: selection
falsepositives:
    - Legitimate use of UltraVNC
level: medium
```
