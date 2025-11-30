```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "splashtop.com" or url.address contains ".api.splashtop.com" or url.address contains ".relay.splashtop.com" or url.address contains ".api.splashtop.eu") or (event.dns.request contains "splashtop.com" or event.dns.request contains ".api.splashtop.com" or event.dns.request contains ".relay.splashtop.com" or event.dns.request contains ".api.splashtop.eu")))
```


# Original Sigma Rule:
```yaml
title: Potential Splashtop Remote RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - splashtop.com
    - '*.api.splashtop.com'
    - '*.relay.splashtop.com'
    - '*.api.splashtop.eu'
  condition: selection
id: 18041451-00ec-4664-8583-db22469e1d84
status: experimental
description: Detects potential network activity of Splashtop Remote RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Splashtop Remote
level: medium
```
