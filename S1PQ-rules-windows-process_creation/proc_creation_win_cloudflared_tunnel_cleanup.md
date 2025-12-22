```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " tunnel " and tgt.process.cmdline contains "cleanup ") and (tgt.process.cmdline contains "-config " or tgt.process.cmdline contains "-connector-id ")))
```


# Original Sigma Rule:
```yaml
title: Cloudflared Tunnel Connections Cleanup
id: 7050bba1-1aed-454e-8f73-3f46f09ce56a
status: test
description: Detects execution of the "cloudflared" tool with the tunnel "cleanup" flag in order to cleanup tunnel connections.
references:
    - https://github.com/cloudflare/cloudflared
    - https://developers.cloudflare.com/cloudflare-one/connections/connect-apps
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-17
modified: 2023-12-21
tags:
    - attack.command-and-control
    - attack.t1102
    - attack.t1090
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' tunnel '
            - 'cleanup '
        CommandLine|contains:
            - '-config '
            - '-connector-id '
    condition: selection
falsepositives:
    - Legitimate usage of Cloudflared.
level: medium
```
