```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\squirrel.exe" or tgt.process.image.path contains "\update.exe") and (tgt.process.cmdline contains " --download " or tgt.process.cmdline contains " --update " or tgt.process.cmdline contains " --updateRollback=") and tgt.process.cmdline contains "http"))
```


# Original Sigma Rule:
```yaml
title: Arbitrary File Download Via Squirrel.EXE
id: 1e75c1cc-c5d4-42aa-ac3d-91b0b68b3b4c
related:
    - id: 45239e6a-b035-4aaf-b339-8ad379fcb67e
      type: similar
    - id: fa4b21c9-0057-4493-b289-2556416ae4d7
      type: obsolete
status: test
description: |
    Detects the usage of the "Squirrel.exe" to download arbitrary files. This binary is part of multiple Electron based software installations (Slack, Teams, Discord, etc.)
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
    selection_download_cli:
        CommandLine|contains:
            - ' --download '
            - ' --update '
            - ' --updateRollback='
    selection_download_http_keyword:
        CommandLine|contains: 'http'
    condition: all of selection_*
falsepositives:
    - Expected FP with some Electron based applications such as (1Clipboard, Beaker Browser, Caret, Discord, GitHub Desktop, etc.)
level: medium
```
