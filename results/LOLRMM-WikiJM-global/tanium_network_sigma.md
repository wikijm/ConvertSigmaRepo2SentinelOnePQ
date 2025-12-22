```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "cloud.tanium.com" or url.address contains ".cloud.tanium.com") or (event.dns.request contains "cloud.tanium.com" or event.dns.request contains ".cloud.tanium.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Tanium RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - cloud.tanium.com
    - '*.cloud.tanium.com'
  condition: selection
id: baa01bb8-f609-4d18-9831-dce77aa66a16
status: experimental
description: Detects potential network activity of Tanium RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Tanium
level: medium
```
