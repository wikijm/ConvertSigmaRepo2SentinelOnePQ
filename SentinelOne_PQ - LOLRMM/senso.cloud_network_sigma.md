```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".senso.cloud" or url.address contains "senso.cloud") or (event.dns.request contains ".senso.cloud" or event.dns.request contains "senso.cloud")))
```


# Original Sigma Rule:
```yaml
title: Potential Senso.cloud RMM Tool Network Activity
id: f24b4c8f-3a80-42f7-b171-dafa5cf50360
status: experimental
description: |
    Detects potential network activity of Senso.cloud RMM tool
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
            - '*.senso.cloud'
            - 'senso.cloud'
    condition: selection
falsepositives:
    - Legitimate use of Senso.cloud
level: medium
```
