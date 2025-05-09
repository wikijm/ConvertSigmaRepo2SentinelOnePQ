```sql
// Translated content (automatically translated on 09-05-2025 01:37:35):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "ehorus.com" or event.dns.request contains "ehorus.com"))
```


# Original Sigma Rule:
```yaml
title: Potential eHorus RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - ehorus.com
  condition: selection
id: c9053241-a95f-4408-b7c6-f898c969bbc1
status: experimental
description: Detects potential network activity of eHorus RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of eHorus
level: medium
```
