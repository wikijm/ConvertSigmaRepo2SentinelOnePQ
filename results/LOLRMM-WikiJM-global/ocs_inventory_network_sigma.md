```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "ocsinventory-ng.org") or (event.dns.request contains "user_managed" or event.dns.request contains "ocsinventory-ng.org")))
```


# Original Sigma Rule:
```yaml
title: Potential OCS inventory RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - ocsinventory-ng.org
  condition: selection
id: cfe53dff-bb84-4eec-aac7-284628e1ac49
status: experimental
description: Detects potential network activity of OCS inventory RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of OCS inventory
level: medium
```
