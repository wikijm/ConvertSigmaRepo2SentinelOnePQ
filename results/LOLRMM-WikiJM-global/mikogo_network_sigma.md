```sql
// Translated content (automatically translated on 23-05-2025 01:38:26):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains ".real-time-collaboration.com" or url.address contains ".mikogo4.com" or url.address contains ".mikogo.com" or url.address contains "mikogo.com") or (event.dns.request contains ".real-time-collaboration.com" or event.dns.request contains ".mikogo4.com" or event.dns.request contains ".mikogo.com" or event.dns.request contains "mikogo.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Mikogo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.real-time-collaboration.com'
    - '*.mikogo4.com'
    - '*.mikogo.com'
    - mikogo.com
  condition: selection
id: 5c555745-beff-4d2b-97ec-56d195946030
status: experimental
description: Detects potential network activity of Mikogo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Mikogo
level: medium
```
