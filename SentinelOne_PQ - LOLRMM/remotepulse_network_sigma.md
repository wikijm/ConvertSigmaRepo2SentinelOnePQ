```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "remotepulse.io" or url.address contains "www.remotepulse.io") or (event.dns.request contains "remotepulse.io" or event.dns.request contains "www.remotepulse.io")))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePulse RMM Tool Network Activity
id: c589692d-c419-5595-a789-83a93775c738
status: experimental
description: |
    Detects potential network activity of RemotePulse RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-07-08
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
            - 'remotepulse.io'
            - 'www.remotepulse.io'
    condition: selection
falsepositives:
    - Legitimate use of RemotePulse
level: medium
```
