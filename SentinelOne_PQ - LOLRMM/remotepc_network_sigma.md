```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".remotedesktop.com" or url.address contains ".remotepc.com" or url.address contains "www.remotepc.com" or url.address contains "remotepc.com") or (event.dns.request contains ".remotedesktop.com" or event.dns.request contains ".remotepc.com" or event.dns.request contains "www.remotepc.com" or event.dns.request contains "remotepc.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePC RMM Tool Network Activity
id: e86ca73e-3392-4338-901e-03cd1fc5c2e2
status: experimental
description: |
    Detects potential network activity of RemotePC RMM tool
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
            - '*.remotedesktop.com'
            - '*.remotepc.com'
            - 'www.remotepc.com'
            - 'remotepc.com'
    condition: selection
falsepositives:
    - Legitimate use of RemotePC
level: medium
```
