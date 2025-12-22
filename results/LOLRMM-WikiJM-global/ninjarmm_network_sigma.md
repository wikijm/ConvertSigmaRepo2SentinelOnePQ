```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ninjarmm.com" or url.address contains ".ninjaone.com" or url.address contains "resources.ninjarmm.com" or url.address contains "ninjaone.com") or (event.dns.request contains ".ninjarmm.com" or event.dns.request contains ".ninjaone.com" or event.dns.request contains "resources.ninjarmm.com" or event.dns.request contains "ninjaone.com")))
```


# Original Sigma Rule:
```yaml
title: Potential NinjaRMM RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.ninjarmm.com'
    - '*.ninjaone.com'
    - resources.ninjarmm.com
    - ninjaone.com
  condition: selection
id: 36fd47e6-13f9-4eb0-a826-8f34e3e1dc0e
status: experimental
description: Detects potential network activity of NinjaRMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NinjaRMM
level: medium
```
