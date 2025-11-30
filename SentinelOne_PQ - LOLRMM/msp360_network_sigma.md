```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".cloudberrylab.com" or url.address contains ".msp360.com" or url.address contains ".mspbackups.com" or url.address contains "msp360.com") or (event.dns.request contains ".cloudberrylab.com" or event.dns.request contains ".msp360.com" or event.dns.request contains ".mspbackups.com" or event.dns.request contains "msp360.com")))
```


# Original Sigma Rule:
```yaml
title: Potential MSP360 RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.cloudberrylab.com'
    - '*.msp360.com'
    - '*.mspbackups.com'
    - msp360.com
  condition: selection
id: 5b9b0cf1-ebcc-4ec2-97b9-af7911ce3624
status: experimental
description: Detects potential network activity of MSP360 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MSP360
level: medium
```
