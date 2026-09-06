```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".kabuto.io" or event.dns.request contains ".kabuto.io"))
```


# Original Sigma Rule:
```yaml
title: Potential Kabuto RMM Tool Network Activity
id: 2e94d749-2e6d-4044-9982-58edf224ecdf
status: experimental
description: |
    Detects potential network activity of Kabuto RMM tool
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
        DestinationHostname|endswith: '*.kabuto.io'
    condition: selection
falsepositives:
    - Legitimate use of Kabuto
level: medium
```
