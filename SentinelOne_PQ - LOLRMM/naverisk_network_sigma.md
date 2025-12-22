```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "naverisk.com") or (event.dns.request contains "user_managed" or event.dns.request contains "naverisk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Naverisk RMM Tool Network Activity
id: d7052972-17c6-441e-aeb1-23a29bf9897f
status: experimental
description: |
    Detects potential network activity of Naverisk RMM tool
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
            - naverisk.com
    condition: selection
falsepositives:
    - Legitimate use of Naverisk
level: medium
```
