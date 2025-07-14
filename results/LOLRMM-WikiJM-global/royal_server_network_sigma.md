```sql
// Translated content (automatically translated on 14-07-2025 01:50:15):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "royalapps.com" or event.dns.request contains "royalapps.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Royal Server RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - royalapps.com
  condition: selection
id: 74218c9f-58b7-44c2-a820-e19e6a7dd939
status: experimental
description: Detects potential network activity of Royal Server RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Royal Server
level: medium
```
