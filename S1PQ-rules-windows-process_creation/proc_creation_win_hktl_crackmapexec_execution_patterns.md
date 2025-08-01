```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline="*cmd.exe /Q /c * 1> \\*\*\* 2>&1*" or tgt.process.cmdline="*cmd.exe /C * > \\*\*\* 2>&1*" or tgt.process.cmdline="*cmd.exe /C * > *\Temp\* 2>&1*" or tgt.process.cmdline contains "powershell.exe -exec bypass -noni -nop -w 1 -C \"" or tgt.process.cmdline contains "powershell.exe -noni -nop -w 1 -enc "))
```


# Original Sigma Rule:
```yaml
title: HackTool - CrackMapExec Execution Patterns
id: 058f4380-962d-40a5-afce-50207d36d7e2
status: stable
description: Detects various execution patterns of the CrackMapExec pentesting framework
references:
    - https://github.com/byt3bl33d3r/CrackMapExec
author: Thomas Patzke
date: 2020-05-22
modified: 2023-11-06
tags:
    - attack.execution
    - attack.t1047
    - attack.t1053
    - attack.t1059.003
    - attack.t1059.001
    - attack.s0106
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # cme/protocols/smb/wmiexec.py (generalized execute_remote and execute_fileless)
            - 'cmd.exe /Q /c * 1> \\\\*\\*\\* 2>&1'
            # cme/protocols/smb/atexec.py:109 (fileless output via share)
            - 'cmd.exe /C * > \\\\*\\*\\* 2>&1'
            # cme/protocols/smb/atexec.py:111 (fileless output via share)
            - 'cmd.exe /C * > *\\Temp\\* 2>&1'
            # https://github.com/byt3bl33d3r/CrackMapExec/blob/d8c50c8cbaf36c29329078662473f75e440978d2/cme/helpers/powershell.py#L136 (PowerShell execution with obfuscation)
            - 'powershell.exe -exec bypass -noni -nop -w 1 -C "'
            # https://github.com/byt3bl33d3r/CrackMapExec/blob/d8c50c8cbaf36c29329078662473f75e440978d2/cme/helpers/powershell.py#L160 (PowerShell execution without obfuscation)
            - 'powershell.exe -noni -nop -w 1 -enc '
    condition: selection
falsepositives:
    - Unknown
level: high
```
