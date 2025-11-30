```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".rudesktop.ru" or url.address contains "rudesktop.ru") or (event.dns.request contains ".rudesktop.ru" or event.dns.request contains "rudesktop.ru")))
```


# Original Sigma Rule:
```yaml
title: Potential RuDesktop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.rudesktop.ru'
    - rudesktop.ru
  condition: selection
id: 3a37ab9b-197e-4d4d-8cb1-43c8cbe70298
status: experimental
description: Detects potential network activity of RuDesktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RuDesktop
level: medium
```
