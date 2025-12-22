```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address="*auth*.aeroadmin.com" or url.address contains "aeroadmin.com") or (event.dns.request="*auth*.aeroadmin.com" or event.dns.request contains "aeroadmin.com")))
```


# Original Sigma Rule:
```yaml
title: Potential AeroAdmin RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - auth*.aeroadmin.com
    - aeroadmin.com
  condition: selection
id: bc4aa1a5-b066-4d36-baa1-fce0df698f6b
status: experimental
description: Detects potential network activity of AeroAdmin RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AeroAdmin
level: medium
```
