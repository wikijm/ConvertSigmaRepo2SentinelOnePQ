```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\ping.exe" and tgt.process.cmdline contains "0x")) | columns src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Ping Hex IP
id: 1a0d4aba-7668-4365-9ce4-6d79ab088dfd
status: test
description: Detects a ping command that uses a hex encoded IP address
references:
    - https://github.com/vysecurity/Aggressor-VYSEC/blob/0d61c80387b9432dab64b8b8a9fb52d20cfef80e/ping.cna
    - https://twitter.com/vysecurity/status/977198418354491392
author: Florian Roth (Nextron Systems)
date: 2018-03-23
modified: 2022-01-07
tags:
    - attack.defense-evasion
    - attack.t1140
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ping.exe'
        CommandLine|contains: '0x'
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high
```
