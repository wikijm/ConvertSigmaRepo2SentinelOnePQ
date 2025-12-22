```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "fixme.it" or event.dns.request contains "fixme.it"))
```


# Original Sigma Rule:
```yaml
title: Potential FixMe RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - fixme.it
  condition: selection
id: 4ae6e481-664f-43dd-9e7f-8dc88b724da3
status: experimental
description: Detects potential network activity of FixMe RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FixMe
level: medium
```
