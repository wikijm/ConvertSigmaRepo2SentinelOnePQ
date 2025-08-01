```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "cmd.exe/c" or tgt.process.cmdline contains "\cmd/c" or tgt.process.cmdline contains "\"cmd/c" or tgt.process.cmdline contains "cmd.exe/k" or tgt.process.cmdline contains "\cmd/k" or tgt.process.cmdline contains "\"cmd/k" or tgt.process.cmdline contains "cmd.exe/r" or tgt.process.cmdline contains "\cmd/r" or tgt.process.cmdline contains "\"cmd/r") or (tgt.process.cmdline contains "/cwhoami" or tgt.process.cmdline contains "/cpowershell" or tgt.process.cmdline contains "/cschtasks" or tgt.process.cmdline contains "/cbitsadmin" or tgt.process.cmdline contains "/ccertutil" or tgt.process.cmdline contains "/kwhoami" or tgt.process.cmdline contains "/kpowershell" or tgt.process.cmdline contains "/kschtasks" or tgt.process.cmdline contains "/kbitsadmin" or tgt.process.cmdline contains "/kcertutil") or (tgt.process.cmdline contains "cmd.exe /c" or tgt.process.cmdline contains "cmd /c" or tgt.process.cmdline contains "cmd.exe /k" or tgt.process.cmdline contains "cmd /k" or tgt.process.cmdline contains "cmd.exe /r" or tgt.process.cmdline contains "cmd /r")) and (not ((tgt.process.cmdline contains "cmd.exe /c " or tgt.process.cmdline contains "cmd /c " or tgt.process.cmdline contains "cmd.exe /k " or tgt.process.cmdline contains "cmd /k " or tgt.process.cmdline contains "cmd.exe /r " or tgt.process.cmdline contains "cmd /r ") or (tgt.process.cmdline contains "AppData\Local\Programs\Microsoft VS Code\resources\app\node_modules" or tgt.process.cmdline contains "cmd.exe/c ." or tgt.process.cmdline="cmd.exe /c")))))
```


# Original Sigma Rule:
```yaml
title: Cmd.EXE Missing Space Characters Execution Anomaly
id: a16980c2-0c56-4de0-9a79-17971979efdd
status: test
description: |
    Detects Windows command lines that miss a space before or after the /c flag when running a command using the cmd.exe.
    This could be a sign of obfuscation of a fat finger problem (typo by the developer).
references:
    - https://twitter.com/cyb3rops/status/1562072617552678912
    - https://ss64.com/nt/cmd.html
author: Florian Roth (Nextron Systems)
date: 2022-08-23
modified: 2023-03-06
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:  # missing space before the /c
        CommandLine|contains:
            - 'cmd.exe/c'
            - '\cmd/c'  # just cmd/c would be prone to false positives
            - '"cmd/c'
            - 'cmd.exe/k'
            - '\cmd/k'  # just cmd/k would be prone to false positives
            - '"cmd/k'
            - 'cmd.exe/r'
            - '\cmd/r'  # just cmd/r would be prone to false positives
            - '"cmd/r'
    selection2: # special cases verified via Virustotal Enterprise search
        CommandLine|contains:
            - '/cwhoami'
            - '/cpowershell'
            - '/cschtasks'
            - '/cbitsadmin'
            - '/ccertutil'
            - '/kwhoami'
            - '/kpowershell'
            - '/kschtasks'
            - '/kbitsadmin'
            - '/kcertutil'
    selection3:  # missing space after the /c
        CommandLine|contains:
            - 'cmd.exe /c'
            - 'cmd /c'
            - 'cmd.exe /k'
            - 'cmd /k'
            - 'cmd.exe /r'
            - 'cmd /r'
    filter_generic:
        CommandLine|contains:
            - 'cmd.exe /c '
            - 'cmd /c '
            - 'cmd.exe /k '
            - 'cmd /k '
            - 'cmd.exe /r '
            - 'cmd /r '
    filter_fp:
        - CommandLine|contains: 'AppData\Local\Programs\Microsoft VS Code\resources\app\node_modules'
        - CommandLine|endswith: 'cmd.exe/c .'
        - CommandLine: 'cmd.exe /c'
    condition: 1 of selection* and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
