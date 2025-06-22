```sql
// Translated content (automatically translated on 22-06-2025 00:58:47):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains ".islonline.net" or url.address contains "rmm.barracudamsp.com" or url.address contains "barracudamsp.com") or (event.dns.request contains ".islonline.net" or event.dns.request contains "rmm.barracudamsp.com" or event.dns.request contains "barracudamsp.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Barracuda RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.islonline.net'
    - rmm.barracudamsp.com
    - barracudamsp.com
  condition: selection
id: e2a52094-af0e-4011-9d65-a0cb49c69ecf
status: experimental
description: Detects potential network activity of Barracuda RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Barracuda
level: medium
```
