```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\sdiagnhost.exe" and (tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\taskkill.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\calc.exe")) and (not ((tgt.process.image.path contains "\\cmd.exe" and tgt.process.cmdline contains "bits") or (tgt.process.image.path contains "\\powershell.exe" and (tgt.process.cmdline contains "-noprofile -" or tgt.process.cmdline contains "-noprofile"))))))
```


# Original Sigma Rule:
```yaml
title: Sdiagnhost Calling Suspicious Child Process
id: f3d39c45-de1a-4486-a687-ab126124f744
status: test
description: Detects sdiagnhost.exe calling a suspicious child process (e.g. used in exploits for Follina / CVE-2022-30190)
references:
    - https://twitter.com/nao_sec/status/1530196847679401984
    - https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e
    - https://app.any.run/tasks/713f05d2-fe78-4b9d-a744-f7c133e3fafb/
    - https://app.any.run/tasks/f420d295-0457-4e9b-9b9e-6732be227583/
    - https://app.any.run/tasks/c4117d9a-f463-461a-b90f-4cd258746798/
author: Nextron Systems, @Kostastsale
date: 2022-06-01
modified: 2024-08-23
tags:
    - attack.defense-evasion
    - attack.t1036
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sdiagnhost.exe'
        Image|endswith:
            # Add more suspicious LOLBins
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
            - '\mshta.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\taskkill.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            # - '\csc.exe'   # https://app.any.run/tasks/f420d295-0457-4e9b-9b9e-6732be227583/
            - '\calc.exe'  # https://app.any.run/tasks/f420d295-0457-4e9b-9b9e-6732be227583/
    filter_main_cmd_bits:
        Image|endswith: '\cmd.exe'
        CommandLine|contains: 'bits'
    filter_main_powershell_noprofile:
        Image|endswith: '\powershell.exe'
        CommandLine|endswith:
            - '-noprofile -'
            - '-noprofile'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
