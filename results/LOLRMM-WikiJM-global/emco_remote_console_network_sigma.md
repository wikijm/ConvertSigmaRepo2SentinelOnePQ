```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "emcosoftware.com") or (event.dns.request contains "user_managed" or event.dns.request contains "emcosoftware.com")))
```


# Original Sigma Rule:
```yaml
title: Potential EMCO Remote Console RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - emcosoftware.com
  condition: selection
id: d76fbf27-bd18-4f77-875f-a80a02b6e8cc
status: experimental
description: Detects potential network activity of EMCO Remote Console RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of EMCO Remote Console
level: medium
```
