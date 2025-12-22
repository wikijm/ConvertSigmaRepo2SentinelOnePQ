```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "new-object" and tgt.process.cmdline contains "text.encoding]::ascii") and (tgt.process.cmdline contains "system.io.compression.deflatestream" or tgt.process.cmdline contains "system.io.streamreader" or tgt.process.cmdline contains "readtoend(")))
```


# Original Sigma Rule:
```yaml
title: Invoke-Obfuscation COMPRESS OBFUSCATION
id: 7eedcc9d-9fdb-4d94-9c54-474e8affc0c7
status: test
description: Detects Obfuscated Powershell via COMPRESS OBFUSCATION
references:
    - https://github.com/SigmaHQ/sigma/issues/1009 # (Task 19)
author: Timur Zinniatullin, oscd.community
date: 2020-10-18
modified: 2022-12-29
tags:
    - attack.defense-evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'new-object'
            - 'text.encoding]::ascii'
        CommandLine|contains:
            - 'system.io.compression.deflatestream'
            - 'system.io.streamreader'
            - 'readtoend('
    condition: selection
falsepositives:
    - Unknown
level: medium
```
