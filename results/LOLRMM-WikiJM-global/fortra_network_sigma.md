```sql
// Translated content (automatically translated on 05-08-2025 01:53:21):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "fortra.com" or event.dns.request contains "fortra.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Fortra RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - fortra.com
  condition: selection
id: 995ea532-e7e8-4b53-a4ae-c6846a58cc75
status: experimental
description: Detects potential network activity of Fortra RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Fortra
level: medium
```
