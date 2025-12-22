```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "iex " or tgt.process.cmdline contains "Invoke-Expression " or tgt.process.cmdline contains "Invoke-Command " or tgt.process.cmdline contains "icm ") and (tgt.process.cmdline contains "cat " or tgt.process.cmdline contains "get-content " or tgt.process.cmdline contains "type ") and tgt.process.cmdline contains " -raw"))
```


# Original Sigma Rule:
```yaml
title: Powershell Inline Execution From A File
id: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
status: test
description: Detects inline execution of PowerShell code from a file
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50
author: frack113
date: 2022-12-25
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_exec:
        CommandLine|contains:
            - 'iex '
            - 'Invoke-Expression '
            - 'Invoke-Command '
            - 'icm '
    selection_read:
        CommandLine|contains:
            - 'cat '
            - 'get-content '
            - 'type '
    selection_raw:
        CommandLine|contains: ' -raw'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
