```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "opsbridge.digital" or event.dns.request contains "opsbridge.digital"))
```


# Original Sigma Rule:
```yaml
title: Potential OpsBridge Agent RMM Tool Network Activity
id: 4b280560-e3ef-5ab4-94de-15969c3e4a76
status: experimental
description: |
    Detects potential network activity of OpsBridge Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-09-02
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: 'opsbridge.digital'
    condition: selection
falsepositives:
    - Legitimate use of OpsBridge Agent
level: medium
```
