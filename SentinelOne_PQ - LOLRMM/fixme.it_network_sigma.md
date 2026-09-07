```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fixme.it" or url.address contains ".techinline.net" or url.address contains "fixme.it") or (event.dns.request contains ".fixme.it" or event.dns.request contains ".techinline.net" or event.dns.request contains "fixme.it")))
```


# Original Sigma Rule:
```yaml
title: Potential FixMe.it RMM Tool Network Activity
id: 5546797c-7d0f-4799-8252-b3c155a6d042
status: experimental
description: |
    Detects potential network activity of FixMe.it RMM tool
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
            - '*.fixme.it'
            - '*.techinline.net'
            - 'fixme.it'
    condition: selection
falsepositives:
    - Legitimate use of FixMe.it
level: medium
```
