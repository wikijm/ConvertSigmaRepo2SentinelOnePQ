```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "myivo-server.software.informer.com" or event.dns.request contains "myivo-server.software.informer.com"))
```


# Original Sigma Rule:
```yaml
title: Potential MyIVO RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - myivo-server.software.informer.com
  condition: selection
id: f1af04ef-8b80-4de2-bc4f-cb0fbe7c5b2a
status: experimental
description: Detects potential network activity of MyIVO RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MyIVO
level: medium
```
