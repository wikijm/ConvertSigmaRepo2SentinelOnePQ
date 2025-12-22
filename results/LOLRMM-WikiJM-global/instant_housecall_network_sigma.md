```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".instanthousecall.com" or url.address contains "secure.instanthousecall.com" or url.address contains ".instanthousecall.net" or url.address contains "instanthousecall.com") or (event.dns.request contains ".instanthousecall.com" or event.dns.request contains "secure.instanthousecall.com" or event.dns.request contains ".instanthousecall.net" or event.dns.request contains "instanthousecall.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Instant Housecall RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.instanthousecall.com'
    - secure.instanthousecall.com
    - '*.instanthousecall.net'
    - instanthousecall.com
  condition: selection
id: 8d93e400-46bd-4d83-af61-d70ea2da9750
status: experimental
description: Detects potential network activity of Instant Housecall RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Instant Housecall
level: medium
```
