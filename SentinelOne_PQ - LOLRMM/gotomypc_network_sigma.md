```sql
// Translated content (automatically translated on 19-05-2025 00:54:43):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".GoToMyPC.com" or event.dns.request contains ".GoToMyPC.com"))
```


# Original Sigma Rule:
```yaml
title: Potential GoToMyPC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.GoToMyPC.com'
  condition: selection
id: a500441d-2754-4a91-8ce1-016086b78b26
status: experimental
description: Detects potential network activity of GoToMyPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GoToMyPC
level: medium
```
