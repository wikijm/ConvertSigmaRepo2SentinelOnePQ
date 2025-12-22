```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "https://github.com/dchapyshev/aspia" or event.dns.request contains "https://github.com/dchapyshev/aspia"))
```


# Original Sigma Rule:
```yaml
title: Potential Aspia RMM Tool Network Activity
id: 413afa8d-3ea2-4561-814a-b77f4d9d652c
status: experimental
description: |
    Detects potential network activity of Aspia RMM tool
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
        DestinationHostname|endswith: https://github.com/dchapyshev/aspia
    condition: selection
falsepositives:
    - Legitimate use of Aspia
level: medium
```
