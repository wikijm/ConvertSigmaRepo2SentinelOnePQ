```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".rmm.datto.com" or url.address contains "cc.centrastage.net" or url.address contains ".cc.centrastage.net") or (event.dns.request contains ".rmm.datto.com" or event.dns.request contains "cc.centrastage.net" or event.dns.request contains ".cc.centrastage.net")))
```


# Original Sigma Rule:
```yaml
title: Potential CentraStage (Now Datto) RMM Tool Network Activity
id: dc92ed7e-9e42-4533-b244-f6d424efab0f
status: experimental
description: |
    Detects potential network activity of CentraStage (Now Datto) RMM tool
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
            - '*.rmm.datto.com'
            - 'cc.centrastage.net'
            - '*.cc.centrastage.net'
    condition: selection
falsepositives:
    - Legitimate use of CentraStage (Now Datto)
level: medium
```
