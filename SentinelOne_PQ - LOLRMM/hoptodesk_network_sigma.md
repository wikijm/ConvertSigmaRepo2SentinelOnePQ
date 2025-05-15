```sql
// Translated content (automatically translated on 15-05-2025 00:50:52):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "signal.hoptodesk.com" or url.address contains "api.hoptodesk.com" or url.address contains "turn.hoptodesk.com" or url.address contains "hoptodesk.com") or (event.dns.request contains "signal.hoptodesk.com" or event.dns.request contains "api.hoptodesk.com" or event.dns.request contains "turn.hoptodesk.com" or event.dns.request contains "hoptodesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential HopToDesk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - signal.hoptodesk.com
    - api.hoptodesk.com
    - turn.hoptodesk.com
    - hoptodesk.com
  condition: selection
status: experimental
description: Detects potential network activity of HopToDesk RMM tool
author: LOLRMM Project
date: 2024/09/19
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of HopToDesk
level: medium
```
