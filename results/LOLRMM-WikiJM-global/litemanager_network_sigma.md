```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".litemanager.ru" or url.address contains ".litemanager.com" or url.address contains "litemanager.com") or (event.dns.request contains ".litemanager.ru" or event.dns.request contains ".litemanager.com" or event.dns.request contains "litemanager.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LiteManager RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.litemanager.ru'
    - '*.litemanager.com'
    - litemanager.com
  condition: selection
id: 4a4aa609-2d4c-4056-a00d-b884785c4678
status: experimental
description: Detects potential network activity of LiteManager RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LiteManager
level: medium
```
