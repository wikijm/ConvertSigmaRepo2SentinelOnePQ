```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "global.rel.tunnels.api.visualstudio.com" or url.address contains ".rel.tunnels.api.visualstudio.com" or url.address contains ".devtunnels.ms") or (event.dns.request contains "global.rel.tunnels.api.visualstudio.com" or event.dns.request contains ".rel.tunnels.api.visualstudio.com" or event.dns.request contains ".devtunnels.ms")))
```


# Original Sigma Rule:
```yaml
title: Potential Visual Studio Dev Tunnel RMM Tool Network Activity
id: e6eb8f0f-6307-498d-87d1-4f008c6c92f5
status: experimental
description: |
    Detects potential network activity of Visual Studio Dev Tunnel RMM tool
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
            - 'global.rel.tunnels.api.visualstudio.com'
            - '*.rel.tunnels.api.visualstudio.com'
            - '*.devtunnels.ms'
    condition: selection
falsepositives:
    - Legitimate use of Visual Studio Dev Tunnel
level: medium
```
