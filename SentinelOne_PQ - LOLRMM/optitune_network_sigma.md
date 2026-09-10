```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".optitune.us" or url.address contains ".opti-tune.com") or (event.dns.request contains ".optitune.us" or event.dns.request contains ".opti-tune.com")))
```


# Original Sigma Rule:
```yaml
title: Potential OptiTune RMM Tool Network Activity
id: 8991fa78-30c2-4504-9503-6b5d9d55878a
status: experimental
description: |
    Detects potential network activity of OptiTune RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.optitune.us'
            - '*.opti-tune.com'
    condition: selection
falsepositives:
    - Legitimate use of OptiTune
level: medium
```
