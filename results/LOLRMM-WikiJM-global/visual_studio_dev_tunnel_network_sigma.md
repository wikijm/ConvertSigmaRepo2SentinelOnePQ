```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "global.rel.tunnels.api.visualstudio.com" or url.address contains ".rel.tunnels.api.visualstudio.com" or url.address contains ".devtunnels.ms") or (event.dns.request contains "global.rel.tunnels.api.visualstudio.com" or event.dns.request contains ".rel.tunnels.api.visualstudio.com" or event.dns.request contains ".devtunnels.ms")))
```


# Original Sigma Rule:
```yaml
title: Potential Visual Studio Dev Tunnel RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - global.rel.tunnels.api.visualstudio.com
    - '*.rel.tunnels.api.visualstudio.com'
    - '*.devtunnels.ms'
  condition: selection
id: 96ab593b-1829-4d12-b5e3-ec7b8d36ce31
status: experimental
description: Detects potential network activity of Visual Studio Dev Tunnel RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Visual Studio Dev Tunnel
level: medium
```
