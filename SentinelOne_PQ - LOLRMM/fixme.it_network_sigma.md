```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".fixme.it" or url.address contains ".techinline.net" or url.address contains "fixme.it" or url.address contains "set.me" or url.address contains "setme.net") or (event.dns.request contains ".fixme.it" or event.dns.request contains ".techinline.net" or event.dns.request contains "fixme.it" or event.dns.request contains "set.me" or event.dns.request contains "setme.net")))
```


# Original Sigma Rule:
```yaml
title: Potential FixMe.it RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.fixme.it'
    - '*.techinline.net'
    - fixme.it
    - '*set.me'
    - '*setme.net'
  condition: selection
id: 67ebb693-3b35-44f5-ab91-d8905ff32eb3
status: experimental
description: Detects potential network activity of FixMe.it RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FixMe.it
level: medium
```
