```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fleetdeck.io" or url.address contains "cognito-idp.us-west-2.amazonaws.com" or url.address contains "fleetdeck.io") or (event.dns.request contains ".fleetdeck.io" or event.dns.request contains "cognito-idp.us-west-2.amazonaws.com" or event.dns.request contains "fleetdeck.io")))
```


# Original Sigma Rule:
```yaml
title: Potential FleetDesk.io RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.fleetdeck.io'
    - cognito-idp.us-west-2.amazonaws.com
    - fleetdeck.io
  condition: selection
id: 129d5713-af89-4506-97f2-ee966aaa34b1
status: experimental
description: Detects potential network activity of FleetDesk.io RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FleetDesk.io
level: medium
```
