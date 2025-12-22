```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "app.gorelo.io" or url.address contains "gorelo-rmm.azurewebsites.net" or url.address contains "gw.usw.gorelo.tech" or url.address contains "lr.rmm.pod1.usw.gorelo.tech" or url.address contains "public.rmm.pod1.usw.gorelo.tech" or url.address contains "r1.rmm.uw.gorelo.tech" or url.address contains "sr.rmm.pod1.usw.gorelo.tech") or (event.dns.request contains "app.gorelo.io" or event.dns.request contains "gorelo-rmm.azurewebsites.net" or event.dns.request contains "gw.usw.gorelo.tech" or event.dns.request contains "lr.rmm.pod1.usw.gorelo.tech" or event.dns.request contains "public.rmm.pod1.usw.gorelo.tech" or event.dns.request contains "r1.rmm.uw.gorelo.tech" or event.dns.request contains "sr.rmm.pod1.usw.gorelo.tech")))
```


# Original Sigma Rule:
```yaml
title: Potential Gorelo RMM RMM Tool Network Activity
id: aa9c32ed-6c98-4c9f-9512-7f55c993872e
status: experimental
description: |
    Detects potential network activity of Gorelo RMM RMM tool
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
            - app.gorelo.io
            - gorelo-rmm.azurewebsites.net
            - gw.usw.gorelo.tech
            - lr.rmm.pod1.usw.gorelo.tech
            - public.rmm.pod1.usw.gorelo.tech
            - r1.rmm.uw.gorelo.tech
            - sr.rmm.pod1.usw.gorelo.tech
    condition: selection
falsepositives:
    - Legitimate use of Gorelo RMM
level: medium
```
