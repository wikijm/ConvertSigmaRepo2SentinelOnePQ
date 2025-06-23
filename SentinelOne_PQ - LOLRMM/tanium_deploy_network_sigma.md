```sql
// Translated content (automatically translated on 23-06-2025 00:57:05):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "tanium.com/products/tanium-deploy" or event.dns.request contains "tanium.com/products/tanium-deploy"))
```


# Original Sigma Rule:
```yaml
title: Potential Tanium Deploy RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - tanium.com/products/tanium-deploy
  condition: selection
id: 3b543ca9-031b-4480-aeb3-a99b2314770d
status: experimental
description: Detects potential network activity of Tanium Deploy RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tanium Deploy
level: medium
```
