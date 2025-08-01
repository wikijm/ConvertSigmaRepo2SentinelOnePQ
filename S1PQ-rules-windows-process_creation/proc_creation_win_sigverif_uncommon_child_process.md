```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\sigverif.exe" and (not (tgt.process.image.path in ("C:\Windows\System32\WerFault.exe","C:\Windows\SysWOW64\WerFault.exe")))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Sigverif.EXE Child Process
id: 7d4aaec2-08ed-4430-8b96-28420e030e04
status: test
description: |
    Detects uncommon child processes spawning from "sigverif.exe", which could indicate potential abuse of the latter as a living of the land binary in order to proxy execution.
references:
    - https://www.hexacorn.com/blog/2018/04/27/i-shot-the-sigverif-exe-the-gui-based-lolbin/
    - https://twitter.com/0gtweet/status/1457676633809330184
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
modified: 2024-08-27
tags:
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sigverif.exe'
    filter_main_werfault:
        Image:
            - 'C:\Windows\System32\WerFault.exe'
            - 'C:\Windows\SysWOW64\WerFault.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
