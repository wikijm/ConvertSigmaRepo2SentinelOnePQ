```sql
// Translated content (automatically translated on 11-05-2025 00:54:56):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "level.io" or event.dns.request contains "level.io"))
```


# Original Sigma Rule:
```yaml
title: Potential Level RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - level.io
  condition: selection
id: b70ec84f-3abc-4a31-92e4-1731e62496f5
status: experimental
description: Detects potential network activity of Level RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Level
level: medium
```
