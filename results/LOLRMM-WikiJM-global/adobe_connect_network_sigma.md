```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".adobeconnect.com" or event.dns.request contains ".adobeconnect.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Adobe Connect RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.adobeconnect.com'
  condition: selection
id: dac102d1-aa4b-43ca-b6e4-872deb21629f
status: experimental
description: Detects potential network activity of Adobe Connect RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Adobe Connect
level: medium
```
