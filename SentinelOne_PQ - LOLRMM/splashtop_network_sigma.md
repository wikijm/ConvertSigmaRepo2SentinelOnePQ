```sql
// Translated content (automatically translated on 07-07-2025 00:58:06):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".splashtop.com" or event.dns.request contains ".splashtop.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.splashtop.com'
  condition: selection
id: 435cfa08-9ab6-4ddf-b68c-580819dbe116
status: experimental
description: Detects potential network activity of Splashtop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop
level: medium
```
