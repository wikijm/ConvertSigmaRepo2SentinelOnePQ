```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "trusted.panorama9.com" or url.address contains "changes.panorama9.com" or url.address contains "panorama9.com") or (event.dns.request contains "trusted.panorama9.com" or event.dns.request contains "changes.panorama9.com" or event.dns.request contains "panorama9.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Panorama9 RMM Tool Network Activity
id: c632c19c-4799-4af6-81dc-57b3212aee9d
status: experimental
description: |
    Detects potential network activity of Panorama9 RMM tool
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
            - trusted.panorama9.com
            - changes.panorama9.com
            - panorama9.com
    condition: selection
falsepositives:
    - Legitimate use of Panorama9
level: medium
```
