```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".islonline.com" or url.address contains ".islonline.net") or (event.dns.request contains ".islonline.com" or event.dns.request contains ".islonline.net")))
```


# Original Sigma Rule:
```yaml
title: Potential ISL Online RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.islonline.com'
    - '*.islonline.net'
  condition: selection
id: e4272154-3b2d-4ce4-b736-b22f7000a025
status: experimental
description: Detects potential network activity of ISL Online RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ISL Online
level: medium
```
