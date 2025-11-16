```sql
// Translated content (automatically translated on 16-11-2025 01:43:32):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "donkz.nl" or event.dns.request contains "donkz.nl"))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Desktop Plus RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - donkz.nl
  condition: selection
id: 0234d2e6-d57e-49a3-898f-bee1543163c5
status: experimental
description: Detects potential network activity of Remote Desktop Plus RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remote Desktop Plus
level: medium
```
