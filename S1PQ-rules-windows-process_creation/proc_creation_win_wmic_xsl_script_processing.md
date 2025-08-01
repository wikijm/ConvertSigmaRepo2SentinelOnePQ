```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\wmic.exe" and (tgt.process.cmdline contains "-format" or tgt.process.cmdline contains "/format" or tgt.process.cmdline contains "–format" or tgt.process.cmdline contains "—format" or tgt.process.cmdline contains "―format")) and (not (tgt.process.cmdline contains "Format:List" or tgt.process.cmdline contains "Format:htable" or tgt.process.cmdline contains "Format:hform" or tgt.process.cmdline contains "Format:table" or tgt.process.cmdline contains "Format:mof" or tgt.process.cmdline contains "Format:value" or tgt.process.cmdline contains "Format:rawxml" or tgt.process.cmdline contains "Format:xml" or tgt.process.cmdline contains "Format:csv"))))
```


# Original Sigma Rule:
```yaml
title: XSL Script Execution Via WMIC.EXE
id: 05c36dd6-79d6-4a9a-97da-3db20298ab2d
status: test
description: |
    Detects the execution of WMIC with the "format" flag to potentially load XSL files.
    Adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
    Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md
author: Timur Zinniatullin, oscd.community, Swachchhanda Shrawan Poudel
date: 2019-10-21
modified: 2024-03-05
tags:
    - attack.defense-evasion
    - attack.t1220
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|windash: '-format'     # wmic process list -FORMAT /? or wmic process list /FORMAT /?
    filter_main_known_format:
        CommandLine|contains:
            - 'Format:List'
            - 'Format:htable'
            - 'Format:hform'
            - 'Format:table'
            - 'Format:mof'
            - 'Format:value'
            - 'Format:rawxml'
            - 'Format:xml'
            - 'Format:csv'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - WMIC.exe FP depend on scripts and administrative methods used in the monitored environment.
    - Static format arguments - https://petri.com/command-line-wmi-part-3
level: medium
```
