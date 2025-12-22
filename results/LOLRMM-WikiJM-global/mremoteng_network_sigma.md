```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "mremoteng.org") or (event.dns.request contains "user_managed" or event.dns.request contains "mremoteng.org")))
```


# Original Sigma Rule:
```yaml
title: Potential mRemoteNG RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - mremoteng.org
  condition: selection
id: e3a3f39b-4957-499f-9cf8-98ba863950ac
status: experimental
description: Detects potential network activity of mRemoteNG RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of mRemoteNG
level: medium
```
