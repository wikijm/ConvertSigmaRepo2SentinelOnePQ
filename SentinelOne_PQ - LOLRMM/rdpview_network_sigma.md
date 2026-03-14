```sql
// Translated content (automatically translated on 14-03-2026 01:07:01):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "systemmanager.ru" or event.dns.request contains "systemmanager.ru"))
```


# Original Sigma Rule:
```yaml
title: Potential RDPView RMM Tool Network Activity
id: 57e3f8cc-3db4-45eb-8272-b62c96ac5c81
status: experimental
description: |
    Detects potential network activity of RDPView RMM tool
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
            - systemmanager.ru
    condition: selection
falsepositives:
    - Legitimate use of RDPView
level: medium
```
