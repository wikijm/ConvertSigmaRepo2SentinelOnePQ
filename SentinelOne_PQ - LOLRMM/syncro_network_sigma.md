```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "kabuto.io" or url.address contains ".syncromsp.com" or url.address contains ".syncroapi.com" or url.address contains "syncromsp.com" or url.address contains "servably.com" or url.address contains "ld.aurelius.host" or url.address contains "app.kabuto.io" or url.address contains ".kabutoservices.com" or url.address contains "repairshopr.com" or url.address contains "kabutoservices.com" or url.address contains "attachments.servably.com") or (event.dns.request contains "kabuto.io" or event.dns.request contains ".syncromsp.com" or event.dns.request contains ".syncroapi.com" or event.dns.request contains "syncromsp.com" or event.dns.request contains "servably.com" or event.dns.request contains "ld.aurelius.host" or event.dns.request contains "app.kabuto.io" or event.dns.request contains ".kabutoservices.com" or event.dns.request contains "repairshopr.com" or event.dns.request contains "kabutoservices.com" or event.dns.request contains "attachments.servably.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Syncro RMM Tool Network Activity
id: 24964039-9f3a-40ac-a2e0-1a346b3278f7
status: experimental
description: |
    Detects potential network activity of Syncro RMM tool
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
            - 'kabuto.io'
            - '*.syncromsp.com'
            - '*.syncroapi.com'
            - 'syncromsp.com'
            - 'servably.com'
            - 'ld.aurelius.host'
            - 'app.kabuto.io'
            - '*.kabutoservices.com'
            - 'repairshopr.com'
            - 'kabutoservices.com'
            - 'attachments.servably.com'
    condition: selection
falsepositives:
    - Legitimate use of Syncro
level: medium
```
