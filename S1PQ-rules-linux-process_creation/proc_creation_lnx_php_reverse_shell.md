```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/php" and (tgt.process.cmdline contains " -r " and tgt.process.cmdline contains "fsockopen") and (tgt.process.cmdline contains "ash" or tgt.process.cmdline contains "bash" or tgt.process.cmdline contains "bsh" or tgt.process.cmdline contains "csh" or tgt.process.cmdline contains "ksh" or tgt.process.cmdline contains "pdksh" or tgt.process.cmdline contains "sh" or tgt.process.cmdline contains "tcsh" or tgt.process.cmdline contains "zsh")))
```


# Original Sigma Rule:
```yaml
title: Potential PHP Reverse Shell
id: c6714a24-d7d5-4283-a36b-3ffd091d5f7e
status: test
description: |
    Detects usage of the PHP CLI with the "-r" flag which allows it to run inline PHP code. The rule looks for calls to the "fsockopen" function which allows the creation of sockets.
    Attackers often leverage this in combination with functions such as "exec" or "fopen" to initiate a reverse shell connection.
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: '/php'
        CommandLine|contains|all:
            - ' -r '
            - 'fsockopen'
        CommandLine|contains:
            - 'ash'
            - 'bash'
            - 'bsh'
            - 'csh'
            - 'ksh'
            - 'pdksh'
            - 'sh'
            - 'tcsh'
            - 'zsh'
    condition: selection
falsepositives:
    - Unknown
level: high
```
