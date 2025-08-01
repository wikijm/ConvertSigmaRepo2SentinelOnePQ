```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/dd" and (tgt.process.cmdline contains "of=" and tgt.process.cmdline contains "/proc/" and tgt.process.cmdline contains "/mem")))
```


# Original Sigma Rule:
```yaml
title: Potential Linux Process Code Injection Via DD Utility
id: 4cad6c64-d6df-42d6-8dae-eb78defdc415
status: test
description: Detects the injection of code by overwriting the memory map of a Linux process using the "dd" Linux command.
references:
    - https://www.aon.com/cyber-solutions/aon_cyber_labs/linux-based-inter-process-code-injection-without-ptrace2/
    - https://github.com/AonCyberLabs/Cexigua/blob/34d338620afae4c6335ba8d8d499e1d7d3d5d7b5/overwrite.sh
author: Joseph Kamau
date: 2023-12-01
tags:
    - attack.defense-evasion
    - attack.t1055.009
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/dd'
        CommandLine|contains|all:
            - 'of='
            - '/proc/'
            - '/mem'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
