```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "ehorus.com" or event.dns.request contains "ehorus.com"))
```


# Original Sigma Rule:
```yaml
title: Potential eHorus RMM Tool Network Activity
id: d077b7a1-3771-4db3-a281-b172ceb16a11
status: experimental
description: |
    Detects potential network activity of eHorus RMM tool
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
        DestinationHostname|endswith: ehorus.com
    condition: selection
falsepositives:
    - Legitimate use of eHorus
level: medium
```
