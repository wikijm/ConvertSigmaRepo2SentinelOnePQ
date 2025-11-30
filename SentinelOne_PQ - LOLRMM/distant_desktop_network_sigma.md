```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".distantdesktop.com" or url.address contains "signalserver.xyz") or (event.dns.request contains ".distantdesktop.com" or event.dns.request contains "signalserver.xyz")))
```


# Original Sigma Rule:
```yaml
title: Potential Distant Desktop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.distantdesktop.com'
    - '*signalserver.xyz'
  condition: selection
id: 05201a97-1e4e-42d8-9dca-3a2af6c53fce
status: experimental
description: Detects potential network activity of Distant Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Distant Desktop
level: medium
```
