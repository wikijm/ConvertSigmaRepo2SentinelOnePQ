```sql
// Translated content (automatically translated on 13-06-2025 01:41:20):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "zerotier.com" or url.address contains ".zerotier.com") or (event.dns.request contains "zerotier.com" or event.dns.request contains ".zerotier.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ZeroTier RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - zerotier.com
    - '*.zerotier.com'
  condition: selection
id: cfc057e5-e86c-46c8-b261-d459149305f7
status: experimental
description: Detects potential network activity of ZeroTier RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ZeroTier
level: medium
```
