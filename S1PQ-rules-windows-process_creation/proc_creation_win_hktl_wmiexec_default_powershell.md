```sql
// Translated content (automatically translated on 05-06-2025 02:04:50):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc")
```


# Original Sigma Rule:
```yaml
title: HackTool - Wmiexec Default Powershell Command
id: 022eaba8-f0bf-4dd9-9217-4604b0bb3bb0
status: test
description: Detects the execution of PowerShell with a specific flag sequence that is used by the Wmiexec script
references:
    - https://github.com/fortra/impacket/blob/f4b848fa27654ca95bc0f4c73dbba8b9c2c9f30a/examples/wmiexec.py
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-08
tags:
    - attack.defense-evasion
    - attack.lateral-movement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
