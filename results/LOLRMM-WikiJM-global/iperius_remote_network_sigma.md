```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".iperiusremote.com" or url.address contains ".iperius.com" or url.address contains ".iperius-rs.com" or url.address contains "iperiusremote.com") or (event.dns.request contains ".iperiusremote.com" or event.dns.request contains ".iperius.com" or event.dns.request contains ".iperius-rs.com" or event.dns.request contains "iperiusremote.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Iperius Remote RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.iperiusremote.com'
    - '*.iperius.com'
    - '*.iperius-rs.com'
    - iperiusremote.com
  condition: selection
id: a0b1f500-b4b2-40c3-9f7e-6ab5bbacf0e9
status: experimental
description: Detects potential network activity of Iperius Remote RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Iperius Remote
level: medium
```
