```sql
// Translated content (automatically translated on 19-07-2025 01:44:19):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "skyfex.com" or url.address contains "deskroll.com" or url.address contains ".deskroll.com") or (event.dns.request contains "skyfex.com" or event.dns.request contains "deskroll.com" or event.dns.request contains ".deskroll.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SkyFex RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - skyfex.com
    - deskroll.com
    - '*.deskroll.com'
  condition: selection
id: 9576d699-5443-4d7b-b464-e2443de129b3
status: experimental
description: Detects potential network activity of SkyFex RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SkyFex
level: medium
```
