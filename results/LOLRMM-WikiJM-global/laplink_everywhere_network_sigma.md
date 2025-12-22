```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "everywhere.laplink.com" or url.address contains "le.laplink.com" or url.address contains "atled.syspectr.com") or (event.dns.request contains "everywhere.laplink.com" or event.dns.request contains "le.laplink.com" or event.dns.request contains "atled.syspectr.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Laplink Everywhere RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - everywhere.laplink.com
    - le.laplink.com
    - atled.syspectr.com
  condition: selection
id: 59176766-d732-472f-9ee1-db3c096ba760
status: experimental
description: Detects potential network activity of Laplink Everywhere RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Laplink Everywhere
level: medium
```
