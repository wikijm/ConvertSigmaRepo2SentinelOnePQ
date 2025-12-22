```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address="*asapi*.aweray.net" or url.address contains "client-api.aweray.com") or (event.dns.request="*asapi*.aweray.net" or event.dns.request contains "client-api.aweray.com")))
```


# Original Sigma Rule:
```yaml
title: Potential AweRay RMM Tool Network Activity
id: 4bcb82fa-7d77-4720-948a-c445b9fb7976
status: experimental
description: |
    Detects potential network activity of AweRay RMM tool
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
            - asapi*.aweray.net
            - client-api.aweray.com
    condition: selection
falsepositives:
    - Legitimate use of AweRay
level: medium
```
