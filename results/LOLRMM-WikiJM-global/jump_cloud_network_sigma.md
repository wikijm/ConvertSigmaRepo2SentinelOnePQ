```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".api.jumpcloud.com" or url.address contains ".assist.jumpcloud.com") or (event.dns.request contains ".api.jumpcloud.com" or event.dns.request contains ".assist.jumpcloud.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Jump Cloud RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.api.jumpcloud.com'
    - '*.assist.jumpcloud.com'
  condition: selection
id: c1e37014-daab-4e69-8224-a2d59eecc118
status: experimental
description: Detects potential network activity of Jump Cloud RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Jump Cloud
level: medium
```
