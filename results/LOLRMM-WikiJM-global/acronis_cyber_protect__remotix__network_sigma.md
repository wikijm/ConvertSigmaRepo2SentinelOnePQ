```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "cloud.acronis.com" or url.address="*agents*-cloud.acronis.com" or url.address contains "gw.remotix.com" or url.address contains "connect.acronis.com") or (event.dns.request contains "cloud.acronis.com" or event.dns.request="*agents*-cloud.acronis.com" or event.dns.request contains "gw.remotix.com" or event.dns.request contains "connect.acronis.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Acronis Cyber Protect (Remotix) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - cloud.acronis.com
    - agents*-cloud.acronis.com
    - gw.remotix.com
    - connect.acronis.com
  condition: selection
id: a7ed0eb9-3d99-47ee-a335-3162430f519c
status: experimental
description: Detects potential network activity of Acronis Cyber Protect (Remotix)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Acronis Cyber Protect (Remotix)
level: medium
```
