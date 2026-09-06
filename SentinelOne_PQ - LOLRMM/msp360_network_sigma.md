```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".cloudberrylab.com" or url.address contains ".msp360.com" or url.address contains ".mspbackups.com" or url.address contains "msp360.com") or (event.dns.request contains ".cloudberrylab.com" or event.dns.request contains ".msp360.com" or event.dns.request contains ".mspbackups.com" or event.dns.request contains "msp360.com")))
```


# Original Sigma Rule:
```yaml
title: Potential MSP360 RMM Tool Network Activity
id: 8340427d-d94f-4325-8c8c-1a0d97343214
status: experimental
description: |
    Detects potential network activity of MSP360 RMM tool
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
            - '*.cloudberrylab.com'
            - '*.msp360.com'
            - '*.mspbackups.com'
            - 'msp360.com'
    condition: selection
falsepositives:
    - Legitimate use of MSP360
level: medium
```
