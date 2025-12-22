```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "prod.addigy.com" or url.address contains "grtmprod.addigy.com" or url.address contains "agents.addigy.com") or (event.dns.request contains "prod.addigy.com" or event.dns.request contains "grtmprod.addigy.com" or event.dns.request contains "agents.addigy.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Addigy RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - prod.addigy.com
    - grtmprod.addigy.com
    - agents.addigy.com
  condition: selection
id: a2f984b5-66c3-4d80-bd47-08394e0c3939
status: experimental
description: Detects potential network activity of Addigy RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Addigy
level: medium
```
