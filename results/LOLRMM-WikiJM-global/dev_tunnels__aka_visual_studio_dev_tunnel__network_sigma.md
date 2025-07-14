```sql
// Translated content (automatically translated on 14-07-2025 01:50:15):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview" or event.dns.request contains "learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview"))
```


# Original Sigma Rule:
```yaml
title: Potential Dev Tunnels (aka Visual Studio Dev Tunnel) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
  condition: selection
id: d241c4b6-c437-4e78-9942-ae798e840204
status: experimental
description: Detects potential network activity of Dev Tunnels (aka Visual Studio
  Dev Tunnel) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Dev Tunnels (aka Visual Studio Dev Tunnel)
level: medium
```
