```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".support.services.microsoft.com" or event.dns.request contains ".support.services.microsoft.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Quick Assist RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.support.services.microsoft.com'
  condition: selection
id: 9608d135-d052-4723-ad00-89a3c9797416
status: experimental
description: Detects potential network activity of Quick Assist RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Quick Assist
level: medium
```
