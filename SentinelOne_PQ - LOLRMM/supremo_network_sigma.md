```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "supremocontrol.com" or url.address contains ".supremocontrol.com" or url.address contains " .nanosystems.it") or (event.dns.request contains "supremocontrol.com" or event.dns.request contains ".supremocontrol.com" or event.dns.request contains " .nanosystems.it")))
```


# Original Sigma Rule:
```yaml
title: Potential Supremo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - supremocontrol.com
    - '*.supremocontrol.com'
    - '* .nanosystems.it'
  condition: selection
id: f6e480a2-9d9e-48ba-abb3-86799bbc999d
status: experimental
description: Detects potential network activity of Supremo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Supremo
level: medium
```
