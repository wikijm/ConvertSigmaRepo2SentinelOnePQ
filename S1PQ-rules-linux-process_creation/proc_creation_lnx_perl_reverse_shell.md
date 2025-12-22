```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/perl" and tgt.process.cmdline contains " -e ") and ((tgt.process.cmdline contains "fdopen(" and tgt.process.cmdline contains "::Socket::INET") or (tgt.process.cmdline contains "Socket" and tgt.process.cmdline contains "connect" and tgt.process.cmdline contains "open" and tgt.process.cmdline contains "exec"))))
```


# Original Sigma Rule:
```yaml
title: Potential Perl Reverse Shell Execution
id: 259df6bc-003f-4306-9f54-4ff1a08fa38e
status: test
description: Detects execution of the perl binary with the "-e" flag and common strings related to potential reverse shell activity
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/perl'
        CommandLine|contains: ' -e '
    selection_content:
        - CommandLine|contains|all:
              - 'fdopen('
              - '::Socket::INET'
        - CommandLine|contains|all:
              - 'Socket'
              - 'connect'
              - 'open'
              - 'exec'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
