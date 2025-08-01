```sql
// Translated content (automatically translated on 01-08-2025 02:00:35):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".internetid.ru" or event.dns.request contains ".internetid.ru"))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Utilities RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.internetid.ru'
  condition: selection
id: 99a2b4e7-a1ee-40ff-8133-088df4428c1b
status: experimental
description: Detects potential network activity of Remote Utilities RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote Utilities
level: medium
```
