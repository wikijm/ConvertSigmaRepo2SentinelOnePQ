```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".alpemix.com" or url.address contains ".teknopars.com") or (event.dns.request contains ".alpemix.com" or event.dns.request contains ".teknopars.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Alpemix RMM Tool Network Activity
id: 0dac95e2-50a7-42dd-96da-322399ebabac
status: experimental
description: |
    Detects potential network activity of Alpemix RMM tool
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
            - '*.alpemix.com'
            - '*.teknopars.com'
    condition: selection
falsepositives:
    - Legitimate use of Alpemix
level: medium
```
