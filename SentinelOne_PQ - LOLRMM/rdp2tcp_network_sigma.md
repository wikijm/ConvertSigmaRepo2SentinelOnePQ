```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "github.com/V-E-O/rdp2tcp") or (event.dns.request contains "user_managed" or event.dns.request contains "github.com/V-E-O/rdp2tcp")))
```


# Original Sigma Rule:
```yaml
title: Potential rdp2tcp RMM Tool Network Activity
id: 7185a584-cd76-4bc8-bae0-1d6a0a3741a9
status: experimental
description: |
    Detects potential network activity of rdp2tcp RMM tool
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
            - github.com/V-E-O/rdp2tcp
    condition: selection
falsepositives:
    - Legitimate use of rdp2tcp
level: medium
```
