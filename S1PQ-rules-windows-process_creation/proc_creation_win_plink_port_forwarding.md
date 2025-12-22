```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.displayName="Command-line SSH, Telnet, and Rlogin client" and tgt.process.cmdline contains " -R "))
```


# Original Sigma Rule:
```yaml
title: Suspicious Plink Port Forwarding
id: 48a61b29-389f-4032-b317-b30de6b95314
status: test
description: Detects suspicious Plink tunnel port forwarding to a local port
references:
    - https://www.real-sec.com/2019/04/bypassing-network-restrictions-through-rdp-tunneling/
    - https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d
author: Florian Roth (Nextron Systems)
date: 2021-01-19
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: 'Command-line SSH, Telnet, and Rlogin client'
        CommandLine|contains: ' -R '
    condition: selection
falsepositives:
    - Administrative activity using a remote port forwarding to a local port
level: high
```
