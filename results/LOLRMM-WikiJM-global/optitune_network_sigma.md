```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".optitune.us" or url.address contains ".opti-tune.com") or (event.dns.request contains ".optitune.us" or event.dns.request contains ".opti-tune.com")))
```


# Original Sigma Rule:
```yaml
title: Potential OptiTune RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.optitune.us'
    - '*.opti-tune.com'
  condition: selection
id: 22949aea-1e6c-4d5a-9caa-069a8561716c
status: experimental
description: Detects potential network activity of OptiTune RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of OptiTune
level: medium
```
