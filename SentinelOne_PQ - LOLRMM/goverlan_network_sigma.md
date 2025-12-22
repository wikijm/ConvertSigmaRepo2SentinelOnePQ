```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "goverlan.com") or (event.dns.request contains "user_managed" or event.dns.request contains "goverlan.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Goverlan RMM Tool Network Activity
id: a74bcadf-a635-4c4b-a522-f685abb84b3d
status: experimental
description: |
    Detects potential network activity of Goverlan RMM tool
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
            - goverlan.com
    condition: selection
falsepositives:
    - Legitimate use of Goverlan
level: medium
```
