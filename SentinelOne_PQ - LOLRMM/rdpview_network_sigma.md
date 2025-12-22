```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "systemmanager.ru/dntu.en/rdp_view.htm") or (event.dns.request contains "user_managed" or event.dns.request contains "systemmanager.ru/dntu.en/rdp_view.htm")))
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
            - user_managed
            - systemmanager.ru/dntu.en/rdp_view.htm
    condition: selection
falsepositives:
    - Legitimate use of RDPView
level: medium
```
