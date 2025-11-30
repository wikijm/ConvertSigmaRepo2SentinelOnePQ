```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".gatherplace.com" or url.address contains ".gatherplace.net" or url.address contains "gatherplace.com") or (event.dns.request contains ".gatherplace.com" or event.dns.request contains ".gatherplace.net" or event.dns.request contains "gatherplace.com")))
```


# Original Sigma Rule:
```yaml
title: Potential GatherPlace-desktop sharing RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.gatherplace.com'
    - '*.gatherplace.net'
    - gatherplace.com
  condition: selection
id: ef086892-3bcd-4b23-91b5-4838a3842152
status: experimental
description: Detects potential network activity of GatherPlace-desktop sharing RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GatherPlace-desktop sharing
level: medium
```
