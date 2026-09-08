```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "dataplicity.com" or url.address contains "www.dataplicity.com" or url.address contains ".dataplicity.com" or url.address contains ".wormhole.dataplicity.com") or (event.dns.request contains "dataplicity.com" or event.dns.request contains "www.dataplicity.com" or event.dns.request contains ".dataplicity.com" or event.dns.request contains ".wormhole.dataplicity.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Dataplicity RMM Tool Network Activity
id: e2dc3562-ae7a-568e-abc9-1b3390d4d66f
status: experimental
description: |
    Detects potential network activity of Dataplicity RMM tool
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
            - 'dataplicity.com'
            - 'www.dataplicity.com'
            - '*.dataplicity.com'
            - '*.wormhole.dataplicity.com'
    condition: selection
falsepositives:
    - Legitimate use of Dataplicity
level: medium
```
