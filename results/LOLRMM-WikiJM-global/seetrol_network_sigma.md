```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "seetrol.co.kr" or event.dns.request contains "seetrol.co.kr"))
```


# Original Sigma Rule:
```yaml
title: Potential Seetrol RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - seetrol.co.kr
  condition: selection
id: 7c4f13a7-2112-432b-9ba4-bbcf9ed5d985
status: experimental
description: Detects potential network activity of Seetrol RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Seetrol
level: medium
```
