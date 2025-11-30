```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".crossloop.com" or url.address contains "crossloop.en.softonic.com") or (event.dns.request contains ".crossloop.com" or event.dns.request contains "crossloop.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential CrossLoop RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.crossloop.com'
    - crossloop.en.softonic.com
  condition: selection
id: bef711ea-7e18-441b-b4c0-609c348fd068
status: experimental
description: Detects potential network activity of CrossLoop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CrossLoop
level: medium
```
