```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "agent.tiflux.com" or url.address contains "app.tiflux.com" or url.address contains "tiflux.com" or url.address contains "www.tiflux.com" or url.address contains "tiflux.com.br" or url.address contains "www.tiflux.com.br" or url.address contains ".tiflux.com" or url.address contains "my.splashtop.com") or (event.dns.request contains "agent.tiflux.com" or event.dns.request contains "app.tiflux.com" or event.dns.request contains "tiflux.com" or event.dns.request contains "www.tiflux.com" or event.dns.request contains "tiflux.com.br" or event.dns.request contains "www.tiflux.com.br" or event.dns.request contains ".tiflux.com" or event.dns.request contains "my.splashtop.com")))
```


# Original Sigma Rule:
```yaml
title: Potential TiFLUX RMM Tool Network Activity
id: 52e259fb-2a86-54a9-84ff-db733436e65a
status: experimental
description: |
    Detects potential network activity of TiFLUX RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - 'agent.tiflux.com'
            - 'app.tiflux.com'
            - 'tiflux.com'
            - 'www.tiflux.com'
            - 'tiflux.com.br'
            - 'www.tiflux.com.br'
            - '*.tiflux.com'
            - 'my.splashtop.com'
    condition: selection
falsepositives:
    - Legitimate use of TiFLUX
level: medium
```
