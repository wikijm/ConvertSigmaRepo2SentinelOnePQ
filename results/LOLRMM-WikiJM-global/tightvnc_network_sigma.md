```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "tightvnc.com") or (event.dns.request contains "user_managed" or event.dns.request contains "tightvnc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TightVNC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - tightvnc.com
  condition: selection
id: d46f2e01-18f7-4d3f-8d6e-1aa0a920897c
status: experimental
description: Detects potential network activity of TightVNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TightVNC
level: medium
```
