```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fleetdeck.io" or url.address contains "fleetdeck.io" or url.address contains "agentmqtt.fleetdeck.io" or url.address contains "checkip.zmazonaws.com") or (event.dns.request contains ".fleetdeck.io" or event.dns.request contains "fleetdeck.io" or event.dns.request contains "agentmqtt.fleetdeck.io" or event.dns.request contains "checkip.zmazonaws.com")))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck.io RMM Tool Network Activity
id: 3a490684-6f45-489b-9941-0848466c09d6
status: experimental
description: |
    Detects potential network activity of FleetDeck.io RMM tool
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
            - '*.fleetdeck.io'
            - 'fleetdeck.io'
            - 'agentmqtt.fleetdeck.io'
            - 'checkip.zmazonaws.com'
    condition: selection
falsepositives:
    - Legitimate use of FleetDeck.io
level: medium
```
