```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".lunixar.com" or url.address contains "lunixar.com" or url.address contains "app.lunixar.com" or url.address contains "socket.lunixar.com" or url.address contains "downloads.lunixar.com" or url.address contains "devrmm.lunixar.com" or url.address contains "mymeetinggoogle.com") or (event.dns.request contains ".lunixar.com" or event.dns.request contains "lunixar.com" or event.dns.request contains "app.lunixar.com" or event.dns.request contains "socket.lunixar.com" or event.dns.request contains "downloads.lunixar.com" or event.dns.request contains "devrmm.lunixar.com" or event.dns.request contains "mymeetinggoogle.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Lunixar RMM Tool Network Activity
id: 1b02b256-0458-5ca0-b182-81f9b3bf99c8
status: experimental
description: |
    Detects potential network activity of Lunixar RMM tool
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
            - '*.lunixar.com'
            - 'lunixar.com'
            - 'app.lunixar.com'
            - 'socket.lunixar.com'
            - 'downloads.lunixar.com'
            - 'devrmm.lunixar.com'
            - 'mymeetinggoogle.com'
    condition: selection
falsepositives:
    - Legitimate use of Lunixar
level: medium
```
