```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "github.com/Mikej81/WebRDP") or (event.dns.request contains "user_managed" or event.dns.request contains "github.com/Mikej81/WebRDP")))
```


# Original Sigma Rule:
```yaml
title: Potential WebRDP RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - github.com/Mikej81/WebRDP
  condition: selection
id: f7766337-77b5-417b-be10-f051c4b65acd
status: experimental
description: Detects potential network activity of WebRDP RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of WebRDP
level: medium
```
