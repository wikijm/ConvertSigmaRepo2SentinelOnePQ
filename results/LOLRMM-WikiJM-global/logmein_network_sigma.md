```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "logmein-gateway.com" or url.address contains ".logmein.com" or url.address contains ".logmein.eu" or url.address contains "logmeinrescue.com" or url.address contains ".logmeininc.com") or (event.dns.request contains "logmein-gateway.com" or event.dns.request contains ".logmein.com" or event.dns.request contains ".logmein.eu" or event.dns.request contains "logmeinrescue.com" or event.dns.request contains ".logmeininc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LogMeIn RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - logmein-gateway.com
    - '*.logmein.com'
    - '*.logmein.eu'
    - logmeinrescue.com
    - '*.logmeininc.com'
  condition: selection
id: 566b2839-f874-48c5-a378-72f82083aa35
status: experimental
description: Detects potential network activity of LogMeIn RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LogMeIn
level: medium
```
