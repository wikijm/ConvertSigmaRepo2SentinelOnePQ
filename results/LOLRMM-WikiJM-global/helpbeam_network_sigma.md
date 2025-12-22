```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "helpbeam.software.informer.com" or event.dns.request contains "helpbeam.software.informer.com"))
```


# Original Sigma Rule:
```yaml
title: Potential HelpBeam RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - helpbeam.software.informer.com
  condition: selection
id: c54ba54d-fc25-4501-89f8-ecebae615d7a
status: experimental
description: Detects potential network activity of HelpBeam RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of HelpBeam
level: medium
```
