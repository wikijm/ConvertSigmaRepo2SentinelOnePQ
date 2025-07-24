```sql
// Translated content (automatically translated on 24-07-2025 01:48:21):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "electric.ai" or event.dns.request contains "electric.ai"))
```


# Original Sigma Rule:
```yaml
title: Potential Electric RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - electric.ai
  condition: selection
id: 13449186-dca1-4550-9b4b-d5eef84f88a2
status: experimental
description: Detects potential network activity of Electric RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Electric
level: medium
```
