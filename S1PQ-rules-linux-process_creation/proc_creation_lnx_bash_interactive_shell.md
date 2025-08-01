```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/bash" and tgt.process.cmdline contains " -i "))
```


# Original Sigma Rule:
```yaml
title: Bash Interactive Shell
id: 6104e693-a7d6-4891-86cb-49a258523559
status: test
description: Detects execution of the bash shell with the interactive flag "-i".
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
    - https://linux.die.net/man/1/bash
author: '@d4ns4n_'
date: 2023-04-07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/bash'
        CommandLine|contains: ' -i '
    condition: selection
falsepositives:
    - Unknown
level: low
```
