```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".ivanticloud.com" or event.dns.request contains ".ivanticloud.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Ivanti Remote Control RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.ivanticloud.com'
  condition: selection
id: 2f3899f6-7982-43c2-ab5b-cba5ccaf5686
status: experimental
description: Detects potential network activity of Ivanti Remote Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ivanti Remote Control
level: medium
```
