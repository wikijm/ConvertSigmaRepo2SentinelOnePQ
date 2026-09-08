```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "desktopcentral.manageengine.com" or url.address contains "desktopcentral.manageengine.com.eu" or url.address contains "desktopcentral.manageengine.cn" or url.address contains ".dms.zoho.com" or url.address contains ".dms.zoho.com.eu" or url.address contains ".-dms.zoho.com.cn") or (event.dns.request contains "desktopcentral.manageengine.com" or event.dns.request contains "desktopcentral.manageengine.com.eu" or event.dns.request contains "desktopcentral.manageengine.cn" or event.dns.request contains ".dms.zoho.com" or event.dns.request contains ".dms.zoho.com.eu" or event.dns.request contains ".-dms.zoho.com.cn")))
```


# Original Sigma Rule:
```yaml
title: Potential Manage Engine (Desktop Central) RMM Tool Network Activity
id: b8539c63-a524-43f9-bc41-05c7723b36e2
status: experimental
description: |
    Detects potential network activity of Manage Engine (Desktop Central) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'desktopcentral.manageengine.com'
            - 'desktopcentral.manageengine.com.eu'
            - 'desktopcentral.manageengine.cn'
            - '*.dms.zoho.com'
            - '*.dms.zoho.com.eu'
            - '*.-dms.zoho.com.cn'
    condition: selection
falsepositives:
    - Legitimate use of Manage Engine (Desktop Central)
level: medium
```
