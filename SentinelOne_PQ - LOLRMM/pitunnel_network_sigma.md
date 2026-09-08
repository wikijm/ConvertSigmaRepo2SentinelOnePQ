```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "pitunnel.com" or url.address contains "www.pitunnel.com" or url.address contains ".pitunnel.com") or (event.dns.request contains "pitunnel.com" or event.dns.request contains "www.pitunnel.com" or event.dns.request contains ".pitunnel.com")))
```


# Original Sigma Rule:
```yaml
title: Potential PiTunnel RMM Tool Network Activity
id: 16988832-407b-5075-8c9b-c22402eed356
status: experimental
description: |
    Detects potential network activity of PiTunnel RMM tool
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
            - 'pitunnel.com'
            - 'www.pitunnel.com'
            - '*.pitunnel.com'
    condition: selection
falsepositives:
    - Legitimate use of PiTunnel
level: medium
```
