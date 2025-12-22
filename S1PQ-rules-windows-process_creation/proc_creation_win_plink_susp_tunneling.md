```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\plink.exe" and tgt.process.cmdline contains ":127.0.0.1:3389") or ((tgt.process.image.path contains "\\plink.exe" and tgt.process.cmdline contains ":3389") and (tgt.process.cmdline contains " -P 443" or tgt.process.cmdline contains " -P 22"))))
```


# Original Sigma Rule:
```yaml
title: Potential RDP Tunneling Via Plink
id: f38ce0b9-5e97-4b47-a211-7dc8d8b871da
related:
    - id: f7d7ebd5-a016-46e2-9c54-f9932f2d386d # ssh.exe
      type: similar
status: test
description: Execution of plink to perform data exfiltration and tunneling
references:
    - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
author: Florian Roth (Nextron Systems)
date: 2022-08-04
modified: 2023-01-27
tags:
    - attack.command-and-control
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection_a:
        Image|endswith: '\plink.exe'
        CommandLine|contains: ':127.0.0.1:3389'
    selection_b1:
        Image|endswith: '\plink.exe'
        CommandLine|contains: ':3389'
    selection_b2:
        CommandLine|contains:
            - ' -P 443'
            - ' -P 22'
    condition: selection_a or all of selection_b*
falsepositives:
    - Unknown
level: high
```
