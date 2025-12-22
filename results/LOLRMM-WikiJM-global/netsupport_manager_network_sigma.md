```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "geo.netsupportsoftware.com" or url.address contains "netsupportmanager.com" or url.address contains ".netsupportmanager.com") or (event.dns.request contains "geo.netsupportsoftware.com" or event.dns.request contains "netsupportmanager.com" or event.dns.request contains ".netsupportmanager.com")))
```


# Original Sigma Rule:
```yaml
title: Potential NetSupport Manager RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - geo.netsupportsoftware.com
    - netsupportmanager.com
    - '*.netsupportmanager.com'
  condition: selection
id: 12c50888-08e9-4d43-b6d5-6d65ea4fcb49
status: experimental
description: Detects potential network activity of NetSupport Manager RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NetSupport Manager
level: medium
```
