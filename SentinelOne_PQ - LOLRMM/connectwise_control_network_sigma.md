```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "live.screenconnect.com" or url.address contains "control.connectwise.com") or (event.dns.request contains "live.screenconnect.com" or event.dns.request contains "control.connectwise.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ConnectWise Control RMM Tool Network Activity
id: 8598b2b0-3a5e-4c6a-b2dc-863d2f130903
status: experimental
description: |
    Detects potential network activity of ConnectWise Control RMM tool
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
            - live.screenconnect.com
            - control.connectwise.com
    condition: selection
falsepositives:
    - Legitimate use of ConnectWise Control
level: medium
```
