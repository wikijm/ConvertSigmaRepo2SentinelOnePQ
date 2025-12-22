```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "tele-desk.com") or (event.dns.request contains "user_managed" or event.dns.request contains "tele-desk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TeleDesktop RMM Tool Network Activity
id: 6d77f583-7194-495b-af7c-9190730aaa31
status: experimental
description: |
    Detects potential network activity of TeleDesktop RMM tool
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
            - tele-desk.com
    condition: selection
falsepositives:
    - Legitimate use of TeleDesktop
level: medium
```
