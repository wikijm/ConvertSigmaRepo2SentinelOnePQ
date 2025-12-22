```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "wangwang.taobao.com" or event.dns.request contains "wangwang.taobao.com"))
```


# Original Sigma Rule:
```yaml
title: Potential AliWangWang-remote-control RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - wangwang.taobao.com
  condition: selection
id: b1ee1673-0951-4e30-b8a8-8843d5dcd9bc
status: experimental
description: Detects potential network activity of AliWangWang-remote-control RMM
  tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of AliWangWang-remote-control
level: medium
```
