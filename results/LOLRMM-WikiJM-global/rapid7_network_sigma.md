```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".analytics.insight.rapid7.com" or url.address contains ".endpoint.ingress.rapid7.com") or (event.dns.request contains ".analytics.insight.rapid7.com" or event.dns.request contains ".endpoint.ingress.rapid7.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Rapid7 RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.analytics.insight.rapid7.com'
    - '*.endpoint.ingress.rapid7.com'
  condition: selection
id: 7f04155f-dc7e-4ed7-ad64-716130f1352e
status: experimental
description: Detects potential network activity of Rapid7 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Rapid7
level: medium
```
