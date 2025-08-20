```sql
// Translated content (automatically translated on 20-08-2025 01:36:25):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".dwservice.net" or event.dns.request contains ".dwservice.net"))
```


# Original Sigma Rule:
```yaml
title: Potential DW Service RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.dwservice.net'
  condition: selection
id: 91d0fd60-1096-40d1-9080-b1793c54e687
status: experimental
description: Detects potential network activity of DW Service RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of DW Service
level: medium
```
