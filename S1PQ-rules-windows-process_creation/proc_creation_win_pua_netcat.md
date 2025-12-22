```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\nc.exe" or tgt.process.image.path contains "\\ncat.exe" or tgt.process.image.path contains "\\netcat.exe") or (tgt.process.cmdline contains " -lvp " or tgt.process.cmdline contains " -lvnp" or tgt.process.cmdline contains " -l -v -p " or tgt.process.cmdline contains " -lv -p " or tgt.process.cmdline contains " -l --proxy-type http " or tgt.process.cmdline contains " -vnl --exec " or tgt.process.cmdline contains " -vnl -e " or tgt.process.cmdline contains " --lua-exec " or tgt.process.cmdline contains " --sh-exec ")))
```


# Original Sigma Rule:
```yaml
title: PUA - Netcat Suspicious Execution
id: e31033fc-33f0-4020-9a16-faf9b31cbf08
status: test
description: Detects execution of Netcat. Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network
references:
    - https://nmap.org/ncat/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1095/T1095.md
    - https://www.revshells.com/
author: frack113, Florian Roth (Nextron Systems)
date: 2021-07-21
modified: 2023-02-08
tags:
    - attack.command-and-control
    - attack.t1095
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        # can not use OriginalFileName as is empty
        Image|endswith:
            - '\nc.exe'
            - '\ncat.exe'
            - '\netcat.exe'
    selection_cmdline:
        # Typical command lines
        CommandLine|contains:
            - ' -lvp '
            - ' -lvnp'
            - ' -l -v -p '
            - ' -lv -p '
            - ' -l --proxy-type http '
            # - ' --exec cmd.exe ' # Not specific enough for netcat
            - ' -vnl --exec '
            - ' -vnl -e '
            - ' --lua-exec '
            - ' --sh-exec '
    condition: 1 of selection_*
falsepositives:
    - Legitimate ncat use
level: high
```
