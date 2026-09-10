```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "rodex.cc" or url.address contains "www.rodex.cc" or url.address contains "<operator-controlled VPS hostname or IP>") or (event.dns.request contains "rodex.cc" or event.dns.request contains "www.rodex.cc" or event.dns.request contains "<operator-controlled VPS hostname or IP>")))
```


# Original Sigma Rule:
```yaml
title: Potential Rodex RMM RMM Tool Network Activity
id: a4905bbe-674f-5c90-8a3a-c4c0b452215d
status: experimental
description: |
    Detects potential network activity of Rodex RMM RMM tool
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
            - 'rodex.cc'
            - 'www.rodex.cc'
            - '<operator-controlled VPS hostname or IP>'
    condition: selection
falsepositives:
    - Legitimate use of Rodex RMM
level: medium
```
