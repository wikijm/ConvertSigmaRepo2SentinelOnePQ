```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ocsinventory-ng.org") or (event.dns.request contains "user_managed" or event.dns.request contains "ocsinventory-ng.org")))
```


# Original Sigma Rule:
```yaml
title: Potential OCS inventory RMM Tool Network Activity
id: 6af3935a-ded4-413a-a175-7edea764de78
status: experimental
description: |
    Detects potential network activity of OCS inventory RMM tool
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
            - ocsinventory-ng.org
    condition: selection
falsepositives:
    - Legitimate use of OCS inventory
level: medium
```
