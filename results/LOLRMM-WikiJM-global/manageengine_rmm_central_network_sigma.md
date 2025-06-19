```sql
// Translated content (automatically translated on 19-06-2025 01:42:08):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "manageengine.com/remote-monitoring-management/" or event.dns.request contains "manageengine.com/remote-monitoring-management/"))
```


# Original Sigma Rule:
```yaml
title: Potential ManageEngine RMM Central RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - manageengine.com/remote-monitoring-management/
  condition: selection
id: 3b13b430-0a0e-4422-a0d1-8b5b0f844b69
status: experimental
description: Detects potential network activity of ManageEngine RMM Central RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ManageEngine RMM Central
level: medium
```
