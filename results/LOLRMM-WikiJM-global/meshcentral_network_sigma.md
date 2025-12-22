```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "meshcentral.com") or (event.dns.request contains "user_managed" or event.dns.request contains "meshcentral.com")))
```


# Original Sigma Rule:
```yaml
title: Potential MeshCentral RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - meshcentral.com
  condition: selection
id: 3003ec5e-21f0-4c8b-8ed6-02a3ee9e3794
status: experimental
description: Detects potential network activity of MeshCentral RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MeshCentral
level: medium
```
