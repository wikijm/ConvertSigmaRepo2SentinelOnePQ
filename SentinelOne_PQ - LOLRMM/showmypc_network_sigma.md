```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".showmypc.com" or url.address contains "showmypc.com") or (event.dns.request contains ".showmypc.com" or event.dns.request contains "showmypc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ShowMyPC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.showmypc.com'
    - showmypc.com
  condition: selection
id: b5e51b9f-67b9-4e77-8dea-93de4f367a8d
status: experimental
description: Detects potential network activity of ShowMyPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ShowMyPC
level: medium
```
