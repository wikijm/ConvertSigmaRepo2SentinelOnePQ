```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "trusted.panorama9.com" or url.address contains "changes.panorama9.com" or url.address contains "panorama9.com") or (event.dns.request contains "trusted.panorama9.com" or event.dns.request contains "changes.panorama9.com" or event.dns.request contains "panorama9.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Panorama9 RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - trusted.panorama9.com
    - changes.panorama9.com
    - panorama9.com
  condition: selection
id: 637c51b3-5ac9-488a-8cae-f387fa503575
status: experimental
description: Detects potential network activity of Panorama9 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Panorama9
level: medium
```
