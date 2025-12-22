```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "meshcentral.com") or (event.dns.request contains "user_managed" or event.dns.request contains "meshcentral.com")))
```


# Original Sigma Rule:
```yaml
title: Potential MeshCentral RMM Tool Network Activity
id: 1ce87195-1117-42e9-b017-4bb59a1b5528
status: experimental
description: |
    Detects potential network activity of MeshCentral RMM tool
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
        DestinationHostname|endswith:
            - user_managed
            - meshcentral.com
    condition: selection
falsepositives:
    - Legitimate use of MeshCentral
level: medium
```
