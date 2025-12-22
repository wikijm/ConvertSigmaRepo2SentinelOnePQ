```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "desktopcentral.manageengine.com" or url.address contains "desktopcentral.manageengine.com.eu" or url.address contains "desktopcentral.manageengine.cn" or url.address contains ".dms.zoho.com" or url.address contains ".dms.zoho.com.eu" or url.address contains ".-dms.zoho.com.cn") or (event.dns.request contains "desktopcentral.manageengine.com" or event.dns.request contains "desktopcentral.manageengine.com.eu" or event.dns.request contains "desktopcentral.manageengine.cn" or event.dns.request contains ".dms.zoho.com" or event.dns.request contains ".dms.zoho.com.eu" or event.dns.request contains ".-dms.zoho.com.cn")))
```


# Original Sigma Rule:
```yaml
title: Potential Manage Engine (Desktop Central) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - desktopcentral.manageengine.com
    - desktopcentral.manageengine.com.eu
    - desktopcentral.manageengine.cn
    - '*.dms.zoho.com'
    - '*.dms.zoho.com.eu'
    - '*.-dms.zoho.com.cn'
  condition: selection
id: 0b0a90db-548e-48b6-9c11-97c408b57dc1
status: experimental
description: Detects potential network activity of Manage Engine (Desktop Central)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Manage Engine (Desktop Central)
level: medium
```
