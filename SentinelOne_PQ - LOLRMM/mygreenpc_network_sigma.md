```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "mygreenpc.com" or event.dns.request contains "mygreenpc.com"))
```


# Original Sigma Rule:
```yaml
title: Potential MyGreenPC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*mygreenpc.com'
  condition: selection
id: 2aa2b1ef-3d1f-40f0-b530-431ea2bea222
status: experimental
description: Detects potential network activity of MyGreenPC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MyGreenPC
level: medium
```
