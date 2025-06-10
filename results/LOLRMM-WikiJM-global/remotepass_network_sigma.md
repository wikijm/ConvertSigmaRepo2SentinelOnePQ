```sql
// Translated content (automatically translated on 10-06-2025 01:42:10):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "remotepass.com" or event.dns.request contains "remotepass.com"))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePass RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - remotepass.com
  condition: selection
id: 82fd5bc7-0dad-4558-950d-1833b2325333
status: experimental
description: Detects potential network activity of RemotePass RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemotePass
level: medium
```
