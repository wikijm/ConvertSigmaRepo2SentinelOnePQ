```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "cloud.tanium.com" or url.address contains ".cloud.tanium.com") or (event.dns.request contains "cloud.tanium.com" or event.dns.request contains ".cloud.tanium.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Tanium RMM Tool Network Activity
id: b0d305ba-1065-4f38-8b5d-9bac2121faad
status: experimental
description: |
    Detects potential network activity of Tanium RMM tool
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
            - 'cloud.tanium.com'
            - '*.cloud.tanium.com'
    condition: selection
falsepositives:
    - Legitimate use of Tanium
level: medium
```
