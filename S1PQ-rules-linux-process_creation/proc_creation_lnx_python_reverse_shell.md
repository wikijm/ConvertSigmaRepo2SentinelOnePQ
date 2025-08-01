```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "python" and (tgt.process.cmdline contains " -c " and tgt.process.cmdline contains "import" and tgt.process.cmdline contains "pty" and tgt.process.cmdline contains "socket" and tgt.process.cmdline contains "spawn" and tgt.process.cmdline contains ".connect")))
```


# Original Sigma Rule:
```yaml
title: Python Reverse Shell Execution Via PTY And Socket Modules
id: 32e62bc7-3de0-4bb1-90af-532978fe42c0
related:
    - id: c4042d54-110d-45dd-a0e1-05c47822c937
      type: similar
status: test
description: |
    Detects the execution of python with calls to the socket and pty module in order to connect and spawn a potential reverse shell.
references:
    - https://www.revshells.com/
author: '@d4ns4n_, Nasreddine Bencherchali (Nextron Systems)'
date: 2023-04-24
modified: 2024-11-04
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'python'
        CommandLine|contains|all:
            - ' -c '
            - 'import'
            - 'pty'
            - 'socket'
            - 'spawn'
            - '.connect'
    condition: selection
falsepositives:
    - Unknown
level: high
```
