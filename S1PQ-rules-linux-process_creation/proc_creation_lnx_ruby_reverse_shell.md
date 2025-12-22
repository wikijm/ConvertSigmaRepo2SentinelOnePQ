```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "ruby" and (tgt.process.cmdline contains " -e" and tgt.process.cmdline contains "rsocket" and tgt.process.cmdline contains "TCPSocket") and (tgt.process.cmdline contains " ash" or tgt.process.cmdline contains " bash" or tgt.process.cmdline contains " bsh" or tgt.process.cmdline contains " csh" or tgt.process.cmdline contains " ksh" or tgt.process.cmdline contains " pdksh" or tgt.process.cmdline contains " sh" or tgt.process.cmdline contains " tcsh")))
```


# Original Sigma Rule:
```yaml
title: Potential Ruby Reverse Shell
id: b8bdac18-c06e-4016-ac30-221553e74f59
status: test
description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
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
        Image|contains: 'ruby'
        CommandLine|contains|all:
            - ' -e'
            - 'rsocket'
            - 'TCPSocket'
        CommandLine|contains:
            - ' ash'
            - ' bash'
            - ' bsh'
            - ' csh'
            - ' ksh'
            - ' pdksh'
            - ' sh'
            - ' tcsh'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
