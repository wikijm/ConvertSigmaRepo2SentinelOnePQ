```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".senso.cloud" or url.address contains "senso.cloud") or (event.dns.request contains ".senso.cloud" or event.dns.request contains "senso.cloud")))
```


# Original Sigma Rule:
```yaml
title: Potential Senso.cloud RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.senso.cloud'
    - senso.cloud
  condition: selection
id: 442fed01-60ef-4b36-996a-9dcaca32fe48
status: experimental
description: Detects potential network activity of Senso.cloud RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Senso.cloud
level: medium
```
