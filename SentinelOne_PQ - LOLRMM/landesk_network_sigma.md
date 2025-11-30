```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ivanticloud.com" or url.address contains ".ivanti.com" or url.address contains "ivanti.com") or (event.dns.request contains ".ivanticloud.com" or event.dns.request contains ".ivanti.com" or event.dns.request contains "ivanti.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LANDesk RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.ivanticloud.com'
    - '*.ivanti.com'
    - ivanti.com
  condition: selection
id: 4733dea8-ac1b-475a-a9f4-cb502e80699e
status: experimental
description: Detects potential network activity of LANDesk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LANDesk
level: medium
```
