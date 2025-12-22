```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "eset.com/me/business/remote-management/remote-administrator/") or (event.dns.request contains "user_managed" or event.dns.request contains "eset.com/me/business/remote-management/remote-administrator/")))
```


# Original Sigma Rule:
```yaml
title: Potential ESET Remote Administrator RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - eset.com/me/business/remote-management/remote-administrator/
  condition: selection
id: d0f8dc3b-f6c4-4293-a6c3-9c5928d5355e
status: experimental
description: Detects potential network activity of ESET Remote Administrator RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ESET Remote Administrator
level: medium
```
