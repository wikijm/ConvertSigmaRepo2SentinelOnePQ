```sql
// Translated content (automatically translated on 29-04-2025 00:50:13):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "asapi-us.aweray.net" or url.address contains "asapi.aweray.net") or (event.dns.request contains "asapi-us.aweray.net" or event.dns.request contains "asapi.aweray.net")))
```


# Original Sigma Rule:
```yaml
title: Potential AweRay (AweSun) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - asapi-us.aweray.net
    - asapi.aweray.net
  condition: selection
id: 03183418-50dd-4d3e-af59-54c1e138a577
status: experimental
description: Detects potential network activity of AweRay (AweSun) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AweRay (AweSun)
level: medium
```
