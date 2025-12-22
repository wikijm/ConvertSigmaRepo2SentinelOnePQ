```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "runsmart.io" or event.dns.request contains "runsmart.io"))
```


# Original Sigma Rule:
```yaml
title: Potential RunSmart RMM Tool Network Activity
id: 5dea5c9a-652f-4ac4-a24e-08ee8bf5df82
status: experimental
description: |
    Detects potential network activity of RunSmart RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: runsmart.io
    condition: selection
falsepositives:
    - Legitimate use of RunSmart
level: medium
```
