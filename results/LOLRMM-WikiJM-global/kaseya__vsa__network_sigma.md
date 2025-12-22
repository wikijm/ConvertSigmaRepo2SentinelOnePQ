```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "deploy01.kaseya.com" or url.address contains "managedsupport.kaseya.net" or url.address contains ".kaseya.net" or url.address contains "kaseya.com") or (event.dns.request contains "deploy01.kaseya.com" or event.dns.request contains "managedsupport.kaseya.net" or event.dns.request contains ".kaseya.net" or event.dns.request contains "kaseya.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Kaseya (VSA) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - deploy01.kaseya.com
    - '*managedsupport.kaseya.net'
    - '*.kaseya.net'
    - kaseya.com
  condition: selection
id: 92bfd790-5430-4154-b3fd-25aad0220766
status: experimental
description: Detects potential network activity of Kaseya (VSA) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Kaseya (VSA)
level: medium
```
