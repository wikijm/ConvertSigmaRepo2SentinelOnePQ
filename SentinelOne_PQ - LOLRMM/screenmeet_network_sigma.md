```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".screenmeet.com" or url.address contains ".scrn.mt") or (event.dns.request contains ".screenmeet.com" or event.dns.request contains ".scrn.mt")))
```


# Original Sigma Rule:
```yaml
title: Potential ScreenMeet RMM Tool Network Activity
id: 7c429563-cd6e-499e-9256-e3ef9fd65ebc
status: experimental
description: |
    Detects potential network activity of ScreenMeet RMM tool
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
            - '*.screenmeet.com'
            - '*.scrn.mt'
    condition: selection
falsepositives:
    - Legitimate use of ScreenMeet
level: medium
```
