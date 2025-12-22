```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".beinsync.net" or url.address contains ".beinsync.com") or (event.dns.request contains ".beinsync.net" or event.dns.request contains ".beinsync.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeInSync RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.beinsync.net'
    - '*.beinsync.com'
  condition: selection
id: 50cf7c20-63d2-4739-8c9e-4e0028962b49
status: experimental
description: Detects potential network activity of BeInSync RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeInSync
level: medium
```
