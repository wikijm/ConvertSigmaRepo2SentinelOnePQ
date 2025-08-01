```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (((tgt.process.image.path contains "/python" or tgt.process.image.path contains "/python2" or tgt.process.image.path contains "/python3") or (tgt.process.image.path contains "/python2." or tgt.process.image.path contains "/python3.")) and (tgt.process.cmdline contains "import pty" or tgt.process.cmdline contains "from pty ") and tgt.process.cmdline contains "spawn"))
```


# Original Sigma Rule:
```yaml
title: Python Spawning Pretty TTY Via PTY Module
id: c4042d54-110d-45dd-a0e1-05c47822c937
related:
    - id: 32e62bc7-3de0-4bb1-90af-532978fe42c0
      type: similar
status: test
description: |
    Detects a python process calling to the PTY module in order to spawn a pretty tty which could be indicative of potential reverse shell activity.
references:
    - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
author: Nextron Systems
date: 2022-06-03
modified: 2024-11-04
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        - Image|endswith:
              - '/python'
              - '/python2'
              - '/python3'
        - Image|contains:
              - '/python2.'  # python image is always of the form ../python3.10; ../python is just a symlink
              - '/python3.'
    selection_cli_import:
        CommandLine|contains:
            - 'import pty'
            - 'from pty '
    selection_cli_spawn:
        CommandLine|contains: 'spawn'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
