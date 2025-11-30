```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "control.connectwise.com" or url.address contains ".connectwise.com" or url.address contains ".screenconnect.com") or (event.dns.request contains "control.connectwise.com" or event.dns.request contains ".connectwise.com" or event.dns.request contains ".screenconnect.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenConnect RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - control.connectwise.com
    - '*.connectwise.com'
    - '*.screenconnect.com'
  condition: selection
id: 745f1940-e16c-42f5-87bb-66f342e0dba8
status: experimental
description: Detects potential network activity of ScreenConnect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ScreenConnect
level: medium
```
