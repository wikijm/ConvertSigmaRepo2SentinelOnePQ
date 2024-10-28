```sql
// Translated content (automatically translated on 28-10-2024 01:21:30):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "dameware.com" or event.dns.request contains "dameware.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Dameware-mini remote control Protocol RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - dameware.com
  condition: selection
id: 64f99179-c36e-4271-aee4-e3e75e866a86
status: experimental
description: Detects potential network activity of Dameware-mini remote control Protocol
  RMM tool
author: LOLRMM Project
date: 2024-08-07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Dameware-mini remote control Protocol
level: medium
```
