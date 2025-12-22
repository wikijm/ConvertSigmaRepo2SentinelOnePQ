```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/nc" or tgt.process.image.path contains "/ncat") and (tgt.process.cmdline contains " -c " or tgt.process.cmdline contains " -e ") and (tgt.process.cmdline contains " ash" or tgt.process.cmdline contains " bash" or tgt.process.cmdline contains " bsh" or tgt.process.cmdline contains " csh" or tgt.process.cmdline contains " ksh" or tgt.process.cmdline contains " pdksh" or tgt.process.cmdline contains " sh" or tgt.process.cmdline contains " tcsh" or tgt.process.cmdline contains "/bin/ash" or tgt.process.cmdline contains "/bin/bash" or tgt.process.cmdline contains "/bin/bsh" or tgt.process.cmdline contains "/bin/csh" or tgt.process.cmdline contains "/bin/ksh" or tgt.process.cmdline contains "/bin/pdksh" or tgt.process.cmdline contains "/bin/sh" or tgt.process.cmdline contains "/bin/tcsh" or tgt.process.cmdline contains "/bin/zsh" or tgt.process.cmdline contains "$IFSash" or tgt.process.cmdline contains "$IFSbash" or tgt.process.cmdline contains "$IFSbsh" or tgt.process.cmdline contains "$IFScsh" or tgt.process.cmdline contains "$IFSksh" or tgt.process.cmdline contains "$IFSpdksh" or tgt.process.cmdline contains "$IFSsh" or tgt.process.cmdline contains "$IFStcsh" or tgt.process.cmdline contains "$IFSzsh")))
```


# Original Sigma Rule:
```yaml
title: Potential Netcat Reverse Shell Execution
id: 7f734ed0-4f47-46c0-837f-6ee62505abd9
status: test
description: Detects execution of netcat with the "-e" flag followed by common shells. This could be a sign of a potential reverse shell setup.
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
    - https://www.hackingtutorials.org/networking/hacking-netcat-part-2-bind-reverse-shells/
    - https://www.infosecademy.com/netcat-reverse-shells/
    - https://man7.org/linux/man-pages/man1/ncat.1.html
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: 2023-04-07
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_nc:
        Image|endswith:
            - '/nc'
            - '/ncat'
    selection_flags:
        CommandLine|contains:
            - ' -c '
            - ' -e '
    selection_shell:
        CommandLine|contains:
            - ' ash'
            - ' bash'
            - ' bsh'
            - ' csh'
            - ' ksh'
            - ' pdksh'
            - ' sh'
            - ' tcsh'
            - '/bin/ash'
            - '/bin/bash'
            - '/bin/bsh'
            - '/bin/csh'
            - '/bin/ksh'
            - '/bin/pdksh'
            - '/bin/sh'
            - '/bin/tcsh'
            - '/bin/zsh'
            - '$IFSash'
            - '$IFSbash'
            - '$IFSbsh'
            - '$IFScsh'
            - '$IFSksh'
            - '$IFSpdksh'
            - '$IFSsh'
            - '$IFStcsh'
            - '$IFSzsh'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
