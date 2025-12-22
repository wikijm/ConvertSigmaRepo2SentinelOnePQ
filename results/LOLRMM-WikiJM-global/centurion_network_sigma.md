```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "centuriontech.com" or event.dns.request contains "centuriontech.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Centurion RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - centuriontech.com
  condition: selection
id: fc93a409-f9df-4dab-abb0-ff489eb32a06
status: experimental
description: Detects potential network activity of Centurion RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Centurion
level: medium
```
