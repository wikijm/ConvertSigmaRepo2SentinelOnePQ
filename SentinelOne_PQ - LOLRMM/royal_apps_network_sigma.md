```sql
// Translated content (automatically translated on 16-08-2025 00:51:57):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential Royal Apps RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
  condition: selection
id: 6c1927ed-a2c9-46de-9ed0-095b1e64ca66
status: experimental
description: Detects potential network activity of Royal Apps RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Royal Apps
level: medium
```
