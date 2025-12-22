```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "realvnc.com/en/connect/download/vnc") or (event.dns.request contains "user_managed" or event.dns.request contains "realvnc.com/en/connect/download/vnc")))
```


# Original Sigma Rule:
```yaml
title: Potential VNC RMM Tool Network Activity
id: 9daee246-13b9-49b9-b68b-520b55b2eea8
status: experimental
description: |
    Detects potential network activity of VNC RMM tool
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
            - realvnc.com/en/connect/download/vnc
    condition: selection
falsepositives:
    - Legitimate use of VNC
level: medium
```
