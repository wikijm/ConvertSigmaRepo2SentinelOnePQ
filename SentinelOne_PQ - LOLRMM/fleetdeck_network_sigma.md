```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "fleetdeck.io" or event.dns.request contains "fleetdeck.io"))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - fleetdeck.io
  condition: selection
id: dfc413ca-4f02-40b5-b4af-c2aa06129b6e
status: experimental
description: Detects potential network activity of FleetDeck RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FleetDeck
level: medium
```
