```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".connect.backdrop.cloud" or url.address contains ".netop.com") or (event.dns.request contains ".connect.backdrop.cloud" or event.dns.request contains ".netop.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (Impero Connect) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.connect.backdrop.cloud'
    - '*.netop.com'
  condition: selection
id: 5501bcd1-7a4f-4dc4-b85f-d7071e5f7f00
status: experimental
description: Detects potential network activity of Netop Remote Control (Impero Connect)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netop Remote Control (Impero Connect)
level: medium
```
