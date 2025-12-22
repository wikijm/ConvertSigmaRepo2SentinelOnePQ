```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".itsupport247.net" or url.address contains "itsupport247.net") or (event.dns.request contains ".itsupport247.net" or event.dns.request contains "itsupport247.net")))
```


# Original Sigma Rule:
```yaml
title: Potential ITSupport247 (ConnectWise) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.itsupport247.net'
    - itsupport247.net
  condition: selection
id: 7c677c95-b608-4705-8573-4cf6f0e2432a
status: experimental
description: Detects potential network activity of ITSupport247 (ConnectWise) RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ITSupport247 (ConnectWise)
level: medium
```
