```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\reg.exe" and (tgt.process.cmdline contains "add " and tgt.process.cmdline contains "SYSTEM\CurrentControlSet\Services\" and tgt.process.cmdline contains " ImagePath ")) and (tgt.process.cmdline contains " -d " or tgt.process.cmdline contains " /d " or tgt.process.cmdline contains " –d " or tgt.process.cmdline contains " —d " or tgt.process.cmdline contains " ―d ")))
```


# Original Sigma Rule:
```yaml
title: Changing Existing Service ImagePath Value Via Reg.EXE
id: 9b0b7ac3-6223-47aa-a3fd-e8f211e637db
status: test
description: |
    Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
    Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
    Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1574.011/T1574.011.md#atomic-test-2---service-imagepath-change-with-regexe
author: frack113
date: 2021-12-30
modified: 2024-03-13
tags:
    - attack.persistence
    - attack.t1574.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains|all:
            - 'add '
            - 'SYSTEM\CurrentControlSet\Services\'
            - ' ImagePath '
    selection_value:
        CommandLine|contains|windash: ' -d '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
