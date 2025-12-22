```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "wen.laplink.com/product/laplink-gold") or (event.dns.request contains "user_managed" or event.dns.request contains "wen.laplink.com/product/laplink-gold")))
```


# Original Sigma Rule:
```yaml
title: Potential Laplink Gold RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - wen.laplink.com/product/laplink-gold
  condition: selection
id: 6e659208-d21e-4981-af48-79bf35b52b87
status: experimental
description: Detects potential network activity of Laplink Gold RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Laplink Gold
level: medium
```
