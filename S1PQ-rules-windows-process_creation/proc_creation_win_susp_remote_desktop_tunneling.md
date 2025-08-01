```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains ":3389" and (tgt.process.cmdline contains " -L " or tgt.process.cmdline contains " -P " or tgt.process.cmdline contains " -R " or tgt.process.cmdline contains " -pw " or tgt.process.cmdline contains " -ssh ")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Desktop Tunneling
id: 8a3038e8-9c9d-46f8-b184-66234a160f6f
status: test
description: Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.
references:
    - https://www.elastic.co/guide/en/security/current/potential-remote-desktop-tunneling-detected.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
tags:
    - attack.lateral-movement
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ':3389' # RDP port and usual SSH tunneling related switches in command line
    selection_opt:
        CommandLine|contains:
            - ' -L '
            - ' -P '
            - ' -R '
            - ' -pw '
            - ' -ssh '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
