```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".internetid.ru" or url.address contains "rmansys.ru") or (event.dns.request contains ".internetid.ru" or event.dns.request contains "rmansys.ru")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Manipulator System RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.internetid.ru'
    - rmansys.ru
  condition: selection
id: ade1656e-2425-423d-ab31-d97438ed9c8f
status: experimental
description: Detects potential network activity of Remote Manipulator System RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote Manipulator System
level: medium
```
