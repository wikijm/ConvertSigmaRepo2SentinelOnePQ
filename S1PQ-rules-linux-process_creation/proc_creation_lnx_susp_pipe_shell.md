```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.cmdline contains "sh -c " or tgt.process.cmdline contains "bash -c ") and ((tgt.process.cmdline contains "| bash " or tgt.process.cmdline contains "| sh " or tgt.process.cmdline contains "|bash " or tgt.process.cmdline contains "|sh ") or (tgt.process.cmdline contains "| bash" or tgt.process.cmdline contains "| sh" or tgt.process.cmdline contains "|bash" or tgt.process.cmdline contains " |sh"))))
```


# Original Sigma Rule:
```yaml
title: Linux Shell Pipe to Shell
id: 880973f3-9708-491c-a77b-2a35a1921158
status: test
description: Detects suspicious process command line that starts with a shell that executes something and finally gets piped into another shell
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022-03-14
modified: 2022-07-26
tags:
    - attack.defense-evasion
    - attack.t1140
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|startswith:
            - 'sh -c '
            - 'bash -c '
    selection_exec:
        - CommandLine|contains:
              - '| bash '
              - '| sh '
              - '|bash '
              - '|sh '
        - CommandLine|endswith:
              - '| bash'
              - '| sh'
              - '|bash'
              - ' |sh'
    condition: all of selection*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
```
