```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".logmeinrescue.com" or url.address contains ".logmeinrescue.eu" or url.address contains "logmeinrescue.com") or (event.dns.request contains ".logmeinrescue.com" or event.dns.request contains ".logmeinrescue.eu" or event.dns.request contains "logmeinrescue.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LogMeIn rescue RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.logmeinrescue.com'
    - '*.logmeinrescue.eu'
    - logmeinrescue.com
  condition: selection
id: eadfb2f5-ad74-4729-ace0-3fc1131880b9
status: experimental
description: Detects potential network activity of LogMeIn rescue RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LogMeIn rescue
level: medium
```
