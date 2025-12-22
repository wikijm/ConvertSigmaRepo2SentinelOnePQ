```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "crosstecsoftware.com/remotecontrol") or (event.dns.request contains "user_managed" or event.dns.request contains "crosstecsoftware.com/remotecontrol")))
```


# Original Sigma Rule:
```yaml
title: Potential CrossTec Remote Control RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - crosstecsoftware.com/remotecontrol
  condition: selection
id: 8aca80db-6f0c-4f83-935a-d2da94e489dc
status: experimental
description: Detects potential network activity of CrossTec Remote Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CrossTec Remote Control
level: medium
```
