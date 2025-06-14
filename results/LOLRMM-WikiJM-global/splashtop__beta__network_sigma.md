```sql
// Translated content (automatically translated on 14-06-2025 01:37:59):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "splashtop.com" or event.dns.request contains "splashtop.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop (Beta) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - splashtop.com
  condition: selection
id: 8a11b1f6-da18-4327-a2fc-235373851669
status: experimental
description: Detects potential network activity of Splashtop (Beta) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop (Beta)
level: medium
```
