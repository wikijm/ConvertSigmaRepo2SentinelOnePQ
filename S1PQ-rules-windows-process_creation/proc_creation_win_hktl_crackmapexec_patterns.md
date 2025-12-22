```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "tasklist /fi " and tgt.process.cmdline contains "Imagename eq lsass.exe") and (tgt.process.cmdline contains "cmd.exe /c " or tgt.process.cmdline contains "cmd.exe /r " or tgt.process.cmdline contains "cmd.exe /k " or tgt.process.cmdline contains "cmd /c " or tgt.process.cmdline contains "cmd /r " or tgt.process.cmdline contains "cmd /k ") and (tgt.process.user contains "AUTHORI" or tgt.process.user contains "AUTORI")) or (tgt.process.cmdline contains "do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump" and tgt.process.cmdline contains "\\Windows\\Temp\\" and tgt.process.cmdline contains " full" and tgt.process.cmdline contains "%%B") or (tgt.process.cmdline contains "tasklist /v /fo csv" and tgt.process.cmdline contains "findstr /i \"lsass\"")))
```


# Original Sigma Rule:
```yaml
title: HackTool - CrackMapExec Process Patterns
id: f26307d8-14cd-47e3-a26b-4b4769f24af6
status: test
description: Detects suspicious process patterns found in logs when CrackMapExec is used
references:
    - https://mpgn.gitbook.io/crackmapexec/smb-protocol/obtaining-credentials/dump-lsass
author: Florian Roth (Nextron Systems)
date: 2022-03-12
modified: 2023-02-13
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_lsass_dump1:
        CommandLine|contains|all:
            - 'tasklist /fi '
            - 'Imagename eq lsass.exe'
        CommandLine|contains:
            - 'cmd.exe /c '
            - 'cmd.exe /r '
            - 'cmd.exe /k '
            - 'cmd /c '
            - 'cmd /r '
            - 'cmd /k '
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    selection_lsass_dump2:
        CommandLine|contains|all:
            - 'do rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump'
            - '\Windows\Temp\'
            - ' full'
            - '%%B'
    selection_procdump:
        CommandLine|contains|all:
            - 'tasklist /v /fo csv'
            - 'findstr /i "lsass"'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
