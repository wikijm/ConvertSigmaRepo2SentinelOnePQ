```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "soti.net/products/soti-pocket-controller" or event.dns.request contains "soti.net/products/soti-pocket-controller"))
```


# Original Sigma Rule:
```yaml
title: Potential Pocket Controller RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - soti.net/products/soti-pocket-controller
  condition: selection
id: bb79c471-cfa9-47cc-9325-b65101bbb1f5
status: experimental
description: Detects potential network activity of Pocket Controller RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pocket Controller
level: medium
```
