```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "cloud.acronis.com" or url.address="*agents*-cloud.acronis.com" or url.address contains "gw.remotix.com" or url.address contains "connect.acronis.com") or (event.dns.request contains "cloud.acronis.com" or event.dns.request="*agents*-cloud.acronis.com" or event.dns.request contains "gw.remotix.com" or event.dns.request contains "connect.acronis.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Acronis Cyber Protect (Remotix) RMM Tool Network Activity
id: 9e6372f6-47e7-4a2b-9306-2d7f2347cb62
status: experimental
description: |
    Detects potential network activity of Acronis Cyber Protect (Remotix) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - cloud.acronis.com
            - agents*-cloud.acronis.com
            - gw.remotix.com
            - connect.acronis.com
    condition: selection
falsepositives:
    - Legitimate use of Acronis Cyber Protect (Remotix)
level: medium
```
