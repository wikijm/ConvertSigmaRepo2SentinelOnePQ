```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "pulseway.com" or event.dns.request contains "pulseway.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Pulseway RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - pulseway.com
  condition: selection
id: 786ef50c-ef11-4ee2-b3fd-84e55f779ed8
status: experimental
description: Detects potential network activity of Pulseway RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pulseway
level: medium
```
