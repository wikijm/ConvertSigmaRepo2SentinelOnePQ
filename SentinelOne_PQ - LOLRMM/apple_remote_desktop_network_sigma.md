```sql
// Translated content (automatically translated on 15-06-2025 00:58:52):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential Apple Remote Desktop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
  condition: selection
id: 3354bc61-36e7-463d-a0cd-8de668b2d0b8
status: experimental
description: Detects potential network activity of Apple Remote Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Apple Remote Desktop
level: medium
```
