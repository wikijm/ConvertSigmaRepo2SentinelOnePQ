```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "n-able.com" or event.dns.request contains "n-able.com"))
```


# Original Sigma Rule:
```yaml
title: Potential N-ABLE Remote Access Software RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - n-able.com
  condition: selection
id: 4eba2de3-3df8-41f8-986f-a9d8b649eac0
status: experimental
description: Detects potential network activity of N-ABLE Remote Access Software RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of N-ABLE Remote Access Software
level: medium
```
