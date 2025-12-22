```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "live.screenconnect.com" or url.address contains "control.connectwise.com") or (event.dns.request contains "live.screenconnect.com" or event.dns.request contains "control.connectwise.com")))
```


# Original Sigma Rule:
```yaml
title: Potential ConnectWise Control RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - live.screenconnect.com
    - control.connectwise.com
  condition: selection
id: 9132f3d7-e95a-423c-80aa-03bae583833c
status: experimental
description: Detects potential network activity of ConnectWise Control RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ConnectWise Control
level: medium
```
