```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "ammyy.com" or url.address contains ".ammyy.com" or url.address contains "136.243.104.235" or url.address contains "136.243.104.242" or url.address contains "136.243.18.122") or (event.dns.request contains "ammyy.com" or event.dns.request contains ".ammyy.com" or event.dns.request contains "136.243.104.235" or event.dns.request contains "136.243.104.242" or event.dns.request contains "136.243.18.122")))
```


# Original Sigma Rule:
```yaml
title: Potential Ammyy Admin RMM Tool Network Activity
id: 68d4c11a-9996-4883-aeda-c081efffa7c7
status: experimental
description: |
    Detects potential network activity of Ammyy Admin RMM tool
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
            - 'ammyy.com'
            - '*.ammyy.com'
            - '136.243.104.235'
            - '136.243.104.242'
            - '136.243.18.122'
    condition: selection
falsepositives:
    - Legitimate use of Ammyy Admin
level: medium
```
