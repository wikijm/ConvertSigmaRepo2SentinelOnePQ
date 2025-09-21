```sql
// Translated content (automatically translated on 21-09-2025 02:02:30):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "python.exe" or tgt.process.image.path contains "python3.exe" or tgt.process.image.path contains "python2.exe") and ((tgt.process.cmdline contains "import pty" and tgt.process.cmdline contains ".spawn(") or tgt.process.cmdline contains "from pty import spawn")))
```


# Original Sigma Rule:
```yaml
title: Python Spawning Pretty TTY on Windows
id: 480e7e51-e797-47e3-8d72-ebfce65b6d8d
related:
    - id: 899133d5-4d7c-4a7f-94ee-27355c879d90
      type: derived
status: test
description: Detects python spawning a pretty tty
references:
    - https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/
author: Nextron Systems
date: 2022-06-03
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - 'python.exe' # no \ bc of e.g. ipython.exe
            - 'python3.exe'
            - 'python2.exe'
    selection_cli_1:
        CommandLine|contains|all:
            - 'import pty'
            - '.spawn('
    selection_cli_2:
        CommandLine|contains: 'from pty import spawn'
    condition: selection_img and 1 of selection_cli_*
falsepositives:
    - Unknown
level: high
```
