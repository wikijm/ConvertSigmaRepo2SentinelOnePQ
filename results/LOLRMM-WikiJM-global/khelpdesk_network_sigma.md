```sql
// Translated content (automatically translated on 19-07-2025 01:44:19):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".khelpdesk.com.br" or event.dns.request contains ".khelpdesk.com.br"))
```


# Original Sigma Rule:
```yaml
title: Potential KHelpDesk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.khelpdesk.com.br'
  condition: selection
id: fb3acb0c-c623-44d5-97fa-3595c4bf8a35
status: experimental
description: Detects potential network activity of KHelpDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of KHelpDesk
level: medium
```
