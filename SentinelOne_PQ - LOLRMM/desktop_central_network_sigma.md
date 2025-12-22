```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "desktopcentral.manageengine.com" or event.dns.request contains "desktopcentral.manageengine.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Desktop Central RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - desktopcentral.manageengine.com
  condition: selection
id: 322f6513-eb99-4f59-a5dc-00cf5f3d020b
status: experimental
description: Detects potential network activity of Desktop Central RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Desktop Central
level: medium
```
