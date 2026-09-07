```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".heartbeatrm.com" or url.address contains "heartbeatrm.com") or (event.dns.request contains ".heartbeatrm.com" or event.dns.request contains "heartbeatrm.com")))
```


# Original Sigma Rule:
```yaml
title: Potential HeartbeatRM RMM Tool Network Activity
id: 6bf78314-f722-50d4-9a80-b0537b72dd9d
status: experimental
description: |
    Detects potential network activity of HeartbeatRM RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.heartbeatrm.com'
            - 'heartbeatrm.com'
    condition: selection
falsepositives:
    - Legitimate use of HeartbeatRM
level: medium
```
