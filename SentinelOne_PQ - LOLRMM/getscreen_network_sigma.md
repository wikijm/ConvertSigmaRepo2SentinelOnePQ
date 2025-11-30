```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "getscreen.me" or url.address contains "GetScreen.me" or url.address contains ".getscreen.me") or (event.dns.request contains "getscreen.me" or event.dns.request contains "GetScreen.me" or event.dns.request contains ".getscreen.me")))
```


# Original Sigma Rule:
```yaml
title: Potential GetScreen RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - getscreen.me
    - GetScreen.me
    - '*.getscreen.me'
  condition: selection
id: 6d5045f0-ab0c-49ef-aeb8-0fc087eb8bc3
status: experimental
description: Detects potential network activity of GetScreen RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GetScreen
level: medium
```
