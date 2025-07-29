```sql
// Translated content (automatically translated on 29-07-2025 02:00:53):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "beanywhere.en.uptodown.com/windows" or url.address contains "beanywhere.com") or (event.dns.request contains "beanywhere.en.uptodown.com/windows" or event.dns.request contains "beanywhere.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeAnyWhere RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - beanywhere.en.uptodown.com/windows
    - beanywhere.com
  condition: selection
id: cea354d4-bf38-4623-b978-3aef587e5566
status: experimental
description: Detects potential network activity of BeAnyWhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeAnyWhere
level: medium
```
