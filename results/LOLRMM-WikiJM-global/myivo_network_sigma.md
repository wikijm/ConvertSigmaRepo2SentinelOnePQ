```sql
// Translated content (automatically translated on 25-01-2026 01:58:47):
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
