```sql
// Translated content (automatically translated on 16-06-2025 01:44:53):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ericom.com") or (event.dns.request contains "user_managed" or event.dns.request contains "ericom.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Ericom Connect RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - ericom.com
  condition: selection
id: 774e5589-c1ad-4dac-bff8-f20069295f06
status: experimental
description: Detects potential network activity of Ericom Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ericom Connect
level: medium
```
