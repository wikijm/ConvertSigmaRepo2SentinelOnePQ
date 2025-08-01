```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\setres.exe" and tgt.process.image.path contains "\choice") and (not (tgt.process.image.path contains "C:\Windows\System32\choice.exe" or tgt.process.image.path contains "C:\Windows\SysWOW64\choice.exe"))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Process Of Setres.EXE
id: 835e75bf-4bfd-47a4-b8a6-b766cac8bcb7
status: test
description: |
    Detects uncommon child process of Setres.EXE.
    Setres.EXE is a Windows server only process and tool that can be used to set the screen resolution.
    It can potentially be abused in order to launch any arbitrary file with a name containing the word "choice" from the current execution path.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Setres/
    - https://twitter.com/0gtweet/status/1583356502340870144
    - https://strontic.github.io/xcyclopedia/library/setres.exe-0E30E4C09637D7A128A37B59A3BC4D09.html
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)
author: '@gott_cyber, Nasreddine Bencherchali (Nextron Systems)'
date: 2022-12-11
modified: 2024-06-26
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\setres.exe'
        Image|contains: '\choice'
    filter_main_legit_location:
        Image|endswith:
            - 'C:\Windows\System32\choice.exe'
            - 'C:\Windows\SysWOW64\choice.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
