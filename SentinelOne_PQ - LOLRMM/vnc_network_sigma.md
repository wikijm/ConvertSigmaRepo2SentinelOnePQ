```sql
// Translated content (automatically translated on 04-05-2025 00:56:05):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "realvnc.com/en/connect/download/vnc") or (event.dns.request contains "user_managed" or event.dns.request contains "realvnc.com/en/connect/download/vnc")))
```


# Original Sigma Rule:
```yaml
title: Potential VNC RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - realvnc.com/en/connect/download/vnc
  condition: selection
id: 9cad51cf-fb13-479a-a44f-3a847a04e882
status: experimental
description: Detects potential network activity of VNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of VNC
level: medium
```
