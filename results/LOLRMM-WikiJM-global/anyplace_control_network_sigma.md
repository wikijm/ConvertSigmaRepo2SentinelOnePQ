```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "anyplace-control.com" or event.dns.request contains "anyplace-control.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Anyplace Control RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - anyplace-control.com
  condition: selection
id: 655792d3-42e6-41e1-a39a-0c6966b8750b
status: experimental
description: Detects potential network activity of Anyplace Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Anyplace Control
level: medium
```
