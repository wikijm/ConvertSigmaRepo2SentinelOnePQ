```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "cl" and tgt.process.cmdline contains "/Trace") or (tgt.process.cmdline contains "clear-log" and tgt.process.cmdline contains "/Trace") or (tgt.process.cmdline contains "sl" and tgt.process.cmdline contains "/e:false") or (tgt.process.cmdline contains "set-log" and tgt.process.cmdline contains "/e:false") or (tgt.process.cmdline contains "logman" and tgt.process.cmdline contains "update" and tgt.process.cmdline contains "trace" and tgt.process.cmdline contains "--p" and tgt.process.cmdline contains "-ets") or tgt.process.cmdline contains "Remove-EtwTraceProvider" or (tgt.process.cmdline contains "Set-EtwTraceProvider" and tgt.process.cmdline contains "0x11")))
```


# Original Sigma Rule:
```yaml
title: ETW Trace Evasion Activity
id: a238b5d0-ce2d-4414-a676-7a531b3d13d6
status: test
description: |
    Detects command line activity that tries to clear or disable any ETW trace log which could be a sign of logging evasion.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
    - https://abuse.io/lockergoga.txt
    - https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
author: '@neu5ron, Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community'
date: 2019-03-22
modified: 2022-06-28
tags:
    - attack.defense-evasion
    - attack.t1070
    - attack.t1562.006
    - car.2016-04-002
logsource:
    category: process_creation
    product: windows
detection:
    selection_clear_1:
        CommandLine|contains|all:
            - 'cl'
            - '/Trace'
    selection_clear_2:
        CommandLine|contains|all:
            - 'clear-log'
            - '/Trace'
    selection_disable_1:
        CommandLine|contains|all:
            - 'sl'
            - '/e:false'
    selection_disable_2:
        CommandLine|contains|all:
            - 'set-log'
            - '/e:false'
    selection_disable_3:   # ETW provider removal from a trace session
        CommandLine|contains|all:
            - 'logman'
            - 'update'
            - 'trace'
            - '--p'
            - '-ets'
    selection_pwsh_remove:   # Autologger provider removal
        CommandLine|contains: 'Remove-EtwTraceProvider'
    selection_pwsh_set:   # Provider “Enable” property modification
        CommandLine|contains|all:
            - 'Set-EtwTraceProvider'
            - '0x11'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
