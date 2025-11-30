```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".my.auvik.com" or url.address contains ".auvik.com" or url.address contains "auvik.com") or (event.dns.request contains ".my.auvik.com" or event.dns.request contains ".auvik.com" or event.dns.request contains "auvik.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Auvik RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.my.auvik.com'
    - '*.auvik.com'
    - auvik.com
  condition: selection
id: f94ee7e0-7d77-4710-814a-1660d2bad2da
status: experimental
description: Detects potential network activity of Auvik RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Auvik
level: medium
```
