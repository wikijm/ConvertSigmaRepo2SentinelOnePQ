```sql
// Translated content (automatically translated on 28-06-2025 00:52:10):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains ".beyondtrustcloud.com" or url.address contains ".bomgarcloud.com" or url.address contains "bomgarcloud.com") or (event.dns.request contains ".beyondtrustcloud.com" or event.dns.request contains ".bomgarcloud.com" or event.dns.request contains "bomgarcloud.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeyondTrust (Bomgar) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.beyondtrustcloud.com'
    - '*.bomgarcloud.com'
    - bomgarcloud.com
  condition: selection
id: 6238e5fb-4629-4c45-b828-c09d66b398d4
status: experimental
description: Detects potential network activity of BeyondTrust (Bomgar) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of BeyondTrust (Bomgar)
level: medium
```
