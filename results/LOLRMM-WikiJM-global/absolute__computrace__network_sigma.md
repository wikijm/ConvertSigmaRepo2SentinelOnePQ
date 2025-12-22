```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "search.namequery.com" or url.address contains "server.absolute.com") or (event.dns.request contains "search.namequery.com" or event.dns.request contains "server.absolute.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Absolute (Computrace) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*search.namequery.com'
    - '*server.absolute.com'
  condition: selection
id: 4b510fc9-5a6e-4cdd-955a-6398c8710ee4
status: experimental
description: Detects potential network activity of Absolute (Computrace) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Absolute (Computrace)
level: medium
```
