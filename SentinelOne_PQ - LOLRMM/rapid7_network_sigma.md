```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".analytics.insight.rapid7.com" or url.address contains ".endpoint.ingress.rapid7.com") or (event.dns.request contains ".analytics.insight.rapid7.com" or event.dns.request contains ".endpoint.ingress.rapid7.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Rapid7 RMM Tool Network Activity
id: 4df2f4fe-07ea-4b8e-a942-dae22b02f59f
status: experimental
description: |
    Detects potential network activity of Rapid7 RMM tool
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
            - '*.analytics.insight.rapid7.com'
            - '*.endpoint.ingress.rapid7.com'
    condition: selection
falsepositives:
    - Legitimate use of Rapid7
level: medium
```
