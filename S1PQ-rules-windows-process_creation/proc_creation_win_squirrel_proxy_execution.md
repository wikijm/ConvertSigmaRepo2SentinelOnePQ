```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\squirrel.exe" or tgt.process.image.path contains "\update.exe") and (tgt.process.cmdline contains "--processStart" or tgt.process.cmdline contains "--processStartAndWait" or tgt.process.cmdline contains "--createShortcut")) and (not ((tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\AppData\Local\Discord\Update.exe" and tgt.process.cmdline contains " --processStart" and tgt.process.cmdline contains "Discord.exe") or ((tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\AppData\Local\GitHubDesktop\Update.exe" and tgt.process.cmdline contains "GitHubDesktop.exe") and (tgt.process.cmdline contains "--createShortcut" or tgt.process.cmdline contains "--processStartAndWait")) or ((tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\AppData\Local\Microsoft\Teams\Update.exe" and tgt.process.cmdline contains "Teams.exe") and (tgt.process.cmdline contains "--processStart" or tgt.process.cmdline contains "--createShortcut")) or ((tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\AppData\Local\yammerdesktop\Update.exe" and tgt.process.cmdline contains "Yammer.exe") and (tgt.process.cmdline contains "--processStart" or tgt.process.cmdline contains "--createShortcut"))))))
```


# Original Sigma Rule:
```yaml
title: Process Proxy Execution Via Squirrel.EXE
id: 45239e6a-b035-4aaf-b339-8ad379fcb67e
related:
    - id: 1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c
      type: similar
    - id: fa4b21c9-0057-4493-b289-2556416ae4d7
      type: obsolete
status: test
description: |
    Detects the usage of the "Squirrel.exe" binary to execute arbitrary processes. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Squirrel/
    - http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
    - http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/
author: Nasreddine Bencherchali (Nextron Systems), Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community
date: 2022-06-09
modified: 2023-11-09
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\squirrel.exe'
            - '\update.exe'
    selection_exec:
        CommandLine|contains:
            - '--processStart'
            - '--processStartAndWait'
            - '--createShortcut'
    filter_optional_discord:
        CommandLine|contains|all:
            - ':\Users\'
            - '\AppData\Local\Discord\Update.exe'
            - ' --processStart'
            - 'Discord.exe'
    filter_optional_github_desktop:
        CommandLine|contains|all:
            - ':\Users\'
            - '\AppData\Local\GitHubDesktop\Update.exe'
            - 'GitHubDesktop.exe'
        CommandLine|contains:
            - '--createShortcut'
            - '--processStartAndWait'
    filter_optional_teams:
        CommandLine|contains|all:
            - ':\Users\'
            - '\AppData\Local\Microsoft\Teams\Update.exe'
            - 'Teams.exe'
        CommandLine|contains:
            - '--processStart'
            - '--createShortcut'
    filter_optional_yammer:
        CommandLine|contains|all:
            - ':\Users\'
            - '\AppData\Local\yammerdesktop\Update.exe'
            - 'Yammer.exe'
        CommandLine|contains:
            - '--processStart'
            - '--createShortcut'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Expected FP with some Electron based applications such as (1Clipboard, Beaker Browser, Caret, Discord, GitHub Desktop, etc.)
level: medium
```
