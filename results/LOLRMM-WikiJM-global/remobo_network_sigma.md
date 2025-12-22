```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "remobo.en.softonic.com") or (event.dns.request contains "user_managed" or event.dns.request contains "remobo.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Remobo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - remobo.en.softonic.com
  condition: selection
id: 93e3bc0d-2fd2-4803-a4bd-06c3ce99dd6e
status: experimental
description: Detects potential network activity of Remobo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Remobo
level: medium
```
