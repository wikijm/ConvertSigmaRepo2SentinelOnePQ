```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "datto.com" or event.dns.request contains "datto.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Datto RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - datto.com
  condition: selection
id: 899970a6-b2b2-4aa4-bcf9-554a37180f47
status: experimental
description: Detects potential network activity of Datto RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Datto
level: medium
```
