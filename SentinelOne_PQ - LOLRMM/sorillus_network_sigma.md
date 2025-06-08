```sql
// Translated content (automatically translated on 08-06-2025 00:58:09):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains ".sorillus.com" or url.address contains "sorillus.com") or (event.dns.request contains ".sorillus.com" or event.dns.request contains "sorillus.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Sorillus RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.sorillus.com'
    - sorillus.com
  condition: selection
id: 45386208-afd8-47ad-835f-9d060c4da5db
status: experimental
description: Detects potential network activity of Sorillus RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Sorillus
level: medium
```
