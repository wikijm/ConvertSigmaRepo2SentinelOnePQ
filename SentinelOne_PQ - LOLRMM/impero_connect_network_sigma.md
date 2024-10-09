```sql
// Translated content (automatically translated on 08-10-2024 15:38:03):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "imperosoftware.com" or event.dns.request contains "imperosoftware.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Impero Connect RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - imperosoftware.com
  condition: selection
id: fc474a0d-c3ae-43b7-9547-65ae0417e4fb
status: experimental
description: Detects potential network activity of Impero Connect RMM tool
author: LOLRMM Project
date: 2024-08-07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Impero Connect
level: medium
```