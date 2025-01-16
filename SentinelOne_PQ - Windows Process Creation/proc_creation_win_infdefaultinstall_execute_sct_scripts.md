```sql
// Translated content (automatically translated on 16-01-2025 01:17:26):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "InfDefaultInstall.exe " and tgt.process.cmdline contains ".inf")) | columns ComputerName,tgt.process.user,tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: InfDefaultInstall.exe .inf Execution
id: ce7cf472-6fcc-490a-9481-3786840b5d9b
status: test
description: Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218/T1218.md#atomic-test-4---infdefaultinstallexe-inf-execution
    - https://lolbas-project.github.io/lolbas/Binaries/Infdefaultinstall/
author: frack113
date: 2021-07-13
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'InfDefaultInstall.exe '
            - '.inf'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium
```
