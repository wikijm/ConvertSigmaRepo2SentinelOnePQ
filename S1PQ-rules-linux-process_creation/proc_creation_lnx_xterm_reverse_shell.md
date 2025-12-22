```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "xterm" and tgt.process.cmdline contains "-display" and tgt.process.cmdline contains ":1"))
```


# Original Sigma Rule:
```yaml
title: Potential Xterm Reverse Shell
id: 4e25af4b-246d-44ea-8563-e42aacab006b
status: test
description: Detects usage of "xterm" as a potential reverse shell tunnel
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_'
date: 2023-04-24
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'xterm'
        CommandLine|contains: '-display'
        CommandLine|endswith: ':1'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
