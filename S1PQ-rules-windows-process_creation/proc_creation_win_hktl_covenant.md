```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "-Sta" and tgt.process.cmdline contains "-Nop" and tgt.process.cmdline contains "-Window" and tgt.process.cmdline contains "Hidden") and (tgt.process.cmdline contains "-Command" or tgt.process.cmdline contains "-EncodedCommand")) or (tgt.process.cmdline contains "sv o (New-Object IO.MemorySteam);sv d " or tgt.process.cmdline contains "mshta file.hta" or tgt.process.cmdline contains "GruntHTTP" or tgt.process.cmdline contains "-EncodedCommand cwB2ACAAbwAgA")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Covenant PowerShell Launcher
id: c260b6db-48ba-4b4a-a76f-2f67644e99d2
status: test
description: Detects suspicious command lines used in Covenant luanchers
references:
    - https://posts.specterops.io/covenant-v0-5-eee0507b85ba
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
date: 2020-06-04
modified: 2023-02-21
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1059.001
    - attack.t1564.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all:
            - '-Sta'
            - '-Nop'
            - '-Window'
            - 'Hidden'
        CommandLine|contains:
            - '-Command'
            - '-EncodedCommand'
    selection_2:
        CommandLine|contains:
            - 'sv o (New-Object IO.MemorySteam);sv d '
            - 'mshta file.hta'
            - 'GruntHTTP'
            - '-EncodedCommand cwB2ACAAbwAgA'
    condition: 1 of selection_*
level: high
```
