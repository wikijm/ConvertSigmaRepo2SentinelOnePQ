```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".superopsbeta.com" or url.address contains "superops.ai" or url.address contains "serv.superopsalpha.com" or url.address contains ".superops.ai" or url.address contains ".superopsalpha.com") or (event.dns.request contains ".superopsbeta.com" or event.dns.request contains "superops.ai" or event.dns.request contains "serv.superopsalpha.com" or event.dns.request contains ".superops.ai" or event.dns.request contains ".superopsalpha.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SuperOps RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.superopsbeta.com'
    - superops.ai
    - serv.superopsalpha.com
    - '*.superops.ai'
    - '*.superopsalpha.com'
  condition: selection
id: a4febe28-4847-4951-aef1-001d0ee0b927
status: experimental
description: Detects potential network activity of SuperOps RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SuperOps
level: medium
```
