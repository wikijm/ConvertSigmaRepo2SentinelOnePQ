```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "sunlogin.oray.com" or url.address contains "client.oray.net") or (event.dns.request contains "sunlogin.oray.com" or event.dns.request contains "client.oray.net")))
```


# Original Sigma Rule:
```yaml
title: Potential SunLogin RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - sunlogin.oray.com
    - client.oray.net
  condition: selection
id: 31635987-f2ef-41e0-b788-a1c0bfd9f096
status: experimental
description: Detects potential network activity of SunLogin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SunLogin
level: medium
```
