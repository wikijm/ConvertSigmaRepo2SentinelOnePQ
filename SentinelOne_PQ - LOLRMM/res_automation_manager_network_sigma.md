```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ivanti.com/") or (event.dns.request contains "user_managed" or event.dns.request contains "ivanti.com/")))
```


# Original Sigma Rule:
```yaml
title: Potential RES Automation Manager RMM Tool Network Activity
id: 89b8bfe3-ba0a-4a8a-aee1-6059ccdd1daa
status: experimental
description: |
    Detects potential network activity of RES Automation Manager RMM tool
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
            - ivanti.com/
    condition: selection
falsepositives:
    - Legitimate use of RES Automation Manager
level: medium
```
