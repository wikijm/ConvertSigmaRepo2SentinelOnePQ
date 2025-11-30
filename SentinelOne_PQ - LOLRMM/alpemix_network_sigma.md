```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".alpemix.com" or url.address contains ".teknopars.com") or (event.dns.request contains ".alpemix.com" or event.dns.request contains ".teknopars.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Alpemix RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.alpemix.com'
    - '*.teknopars.com'
  condition: selection
id: 3de99ba1-bfc3-4569-a352-0f1b1b455a78
status: experimental
description: Detects potential network activity of Alpemix RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Alpemix
level: medium
```
