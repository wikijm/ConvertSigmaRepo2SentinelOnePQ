```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\expand.exe" and (tgt.process.cmdline contains "-F:" or tgt.process.cmdline contains "/F:" or tgt.process.cmdline contains "–F:" or tgt.process.cmdline contains "—F:" or tgt.process.cmdline contains "―F:")) and ((tgt.process.cmdline contains ":\Perflogs\" or tgt.process.cmdline contains ":\ProgramData" or tgt.process.cmdline contains ":\Users\Public\" or tgt.process.cmdline contains ":\Windows\Temp\" or tgt.process.cmdline contains "\Admin$\" or tgt.process.cmdline contains "\AppData\Local\Temp\" or tgt.process.cmdline contains "\AppData\Roaming\" or tgt.process.cmdline contains "\C$\" or tgt.process.cmdline contains "\Temporary Internet") or ((tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Favorites\") or (tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Favourites\") or (tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Contacts\"))) and (not (src.process.image.path="C:\Program Files (x86)\Dell\UpdateService\ServiceShell.exe" and tgt.process.cmdline contains "C:\ProgramData\Dell\UpdateService\Temp\"))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Cabinet File Expansion
id: 9f107a84-532c-41af-b005-8d12a607639f
status: test
description: Detects the expansion or decompression of cabinet files from potentially suspicious or uncommon locations, e.g. seen in Iranian MeteorExpress related attacks
references:
    - https://labs.sentinelone.com/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll
    - https://blog.malwarebytes.com/threat-intelligence/2021/08/new-variant-of-konni-malware-used-in-campaign-targetting-russia/
author: Bhabesh Raj, X__Junior (Nextron Systems)
date: 2021-07-30
modified: 2024-11-13
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\expand.exe'
        CommandLine|contains|windash: '-F:'
    selection_folders_1:
        CommandLine|contains:
            - ':\Perflogs\'
            - ':\ProgramData'
            - ':\Users\Public\'
            - ':\Windows\Temp\'
            - '\Admin$\'
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\C$\'
            - '\Temporary Internet'
    selection_folders_2:
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Favorites\'
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Favourites\'
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Contacts\'
    filter_optional_dell:
        # Launched by Dell ServiceShell.exe
        ParentImage: 'C:\Program Files (x86)\Dell\UpdateService\ServiceShell.exe'
        CommandLine|contains: 'C:\ProgramData\Dell\UpdateService\Temp\'
    condition: selection_cmd and 1 of selection_folders_* and not 1 of filter_optional_*
falsepositives:
    - System administrator Usage
level: medium
```
