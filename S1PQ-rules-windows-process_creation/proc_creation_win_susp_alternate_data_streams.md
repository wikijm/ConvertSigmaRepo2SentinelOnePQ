```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "txt:" and ((tgt.process.cmdline contains "type " and tgt.process.cmdline contains " > ") or (tgt.process.cmdline contains "makecab " and tgt.process.cmdline contains ".cab") or (tgt.process.cmdline contains "reg " and tgt.process.cmdline contains " export ") or (tgt.process.cmdline contains "regedit " and tgt.process.cmdline contains " /E ") or (tgt.process.cmdline contains "esentutl " and tgt.process.cmdline contains " /y " and tgt.process.cmdline contains " /d " and tgt.process.cmdline contains " /o "))))
```


# Original Sigma Rule:
```yaml
title: Execute From Alternate Data Streams
id: 7f43c430-5001-4f8b-aaa9-c3b88f18fa5c
status: test
description: Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md
author: frack113
date: 2021-09-01
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_stream:
        CommandLine|contains: 'txt:'
    selection_tools_type:
        CommandLine|contains|all:
            - 'type '
            - ' > '
    selection_tools_makecab:
        CommandLine|contains|all:
            - 'makecab '
            - '.cab'
    selection_tools_reg:
        CommandLine|contains|all:
            - 'reg '
            - ' export '
    selection_tools_regedit:
        CommandLine|contains|all:
            - 'regedit '
            - ' /E '
    selection_tools_esentutl:
        CommandLine|contains|all:
            - 'esentutl '
            - ' /y '
            - ' /d '
            - ' /o '
    condition: selection_stream and (1 of selection_tools_*)
falsepositives:
    - Unknown
level: medium
```
