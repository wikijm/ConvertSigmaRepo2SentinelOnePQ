```sql
// Translated content (automatically translated on 19-07-2025 01:44:19):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "resources.doradosoftware.com/cruz-rmm" or event.dns.request contains "resources.doradosoftware.com/cruz-rmm"))
```


# Original Sigma Rule:
```yaml
title: Potential Cruz RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - resources.doradosoftware.com/cruz-rmm
  condition: selection
id: e3090529-bfd4-4a80-a961-519340833ece
status: experimental
description: Detects potential network activity of Cruz RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Cruz
level: medium
```
