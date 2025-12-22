```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "tunnel " and tgt.process.cmdline contains "service" and tgt.process.cmdline contains "internal-run" and tgt.process.cmdline contains "tunnel-service.log"))
```


# Original Sigma Rule:
```yaml
title: Visual Studio Code Tunnel Service Installation
id: 30bf1789-379d-4fdc-900f-55cd0a90a801
status: test
description: Detects the installation of VsCode tunnel (code-tunnel) as a service.
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://code.visualstudio.com/docs/remote/tunnels
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-10-25
tags:
    - attack.command-and-control
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'tunnel '
            - 'service'
            - 'internal-run'
            - 'tunnel-service.log'
    condition: selection
falsepositives:
    - Legitimate installation of code-tunnel as a service
level: medium
```
