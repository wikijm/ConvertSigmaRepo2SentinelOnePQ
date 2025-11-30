```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "fleetdeck.io" or event.dns.request contains "fleetdeck.io"))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDeck.io RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - fleetdeck.io
  condition: selection
id: 430ac9bb-c9db-4f8f-85c3-b0db33be9d26
status: experimental
description: Detects potential network activity of FleetDeck.io RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FleetDeck.io
level: medium
```
