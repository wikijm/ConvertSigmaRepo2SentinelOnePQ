```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".weezo.me" or url.address contains "weezo.net" or url.address contains ".weezo.net" or url.address contains "weezo.en.softonic.com") or (event.dns.request contains ".weezo.me" or event.dns.request contains "weezo.net" or event.dns.request contains ".weezo.net" or event.dns.request contains "weezo.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Weezo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.weezo.me'
    - weezo.net
    - '*.weezo.net'
    - weezo.en.softonic.com
  condition: selection
id: 4ccf2652-03ea-4740-aa03-8f7c57f904e1
status: experimental
description: Detects potential network activity of Weezo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Weezo
level: medium
```
