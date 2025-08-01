```sql
// Translated content (automatically translated on 01-08-2025 02:00:35):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "beamyourscreen.com" or url.address contains ".beamyourscreen.com") or (event.dns.request contains "beamyourscreen.com" or event.dns.request contains ".beamyourscreen.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeamYourScreen RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - beamyourscreen.com
    - '*.beamyourscreen.com'
  condition: selection
id: ad4210bf-66b5-4c7e-b20b-f71d609dc5a7
status: experimental
description: Detects potential network activity of BeamYourScreen RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeamYourScreen
level: medium
```
