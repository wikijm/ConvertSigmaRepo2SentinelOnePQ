```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "level.io" or url.address contains "builds.level.io" or url.address contains "agents.level.io" or url.address contains "online.level.io" or url.address contains "downloads.io") or (event.dns.request contains "level.io" or event.dns.request contains "builds.level.io" or event.dns.request contains "agents.level.io" or event.dns.request contains "online.level.io" or event.dns.request contains "downloads.io")))
```


# Original Sigma Rule:
```yaml
title: Potential Level RMM Tool Network Activity
id: ed6be521-b6af-47df-b0c9-7474d10f328f
status: experimental
description: |
    Detects potential network activity of Level RMM tool
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
            - level.io
            - builds.level.io
            - agents.level.io
            - online.level.io
            - downloads.io
    condition: selection
falsepositives:
    - Legitimate use of Level
level: medium
```
