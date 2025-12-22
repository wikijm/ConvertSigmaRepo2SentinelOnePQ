```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\minesweeper.exe" or src.process.image.path contains "\\winver.exe" or src.process.image.path contains "\\bitsadmin.exe") or ((src.process.image.path contains "\\csrss.exe" or src.process.image.path contains "\\certutil.exe" or src.process.image.path contains "\\eventvwr.exe" or src.process.image.path contains "\\calc.exe" or src.process.image.path contains "\\notepad.exe") and (not ((tgt.process.image.path contains "\\WerFault.exe" or tgt.process.image.path contains "\\wermgr.exe" or tgt.process.image.path contains "\\conhost.exe" or tgt.process.image.path contains "\\mmc.exe" or tgt.process.image.path contains "\\win32calc.exe" or tgt.process.image.path contains "\\notepad.exe") or not (tgt.process.image.path matches "\.*"))))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process Parents
id: cbec226f-63d9-4eca-9f52-dfb6652f24df
status: test
description: Detects suspicious parent processes that should not have any children or should only have a single possible child program
references:
    - https://twitter.com/x86matthew/status/1505476263464607744?s=12
    - https://svch0st.medium.com/stats-from-hunting-cobalt-strike-beacons-c17e56255f9b
author: Florian Roth (Nextron Systems)
date: 2022-03-21
modified: 2022-09-08
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\minesweeper.exe'
            - '\winver.exe'
            - '\bitsadmin.exe'
    selection_special:
        ParentImage|endswith:
            - '\csrss.exe'
            - '\certutil.exe'
         # - '\schtasks.exe'
            - '\eventvwr.exe'
            - '\calc.exe'
            - '\notepad.exe'
    filter_special:
        Image|endswith:
            - '\WerFault.exe'
            - '\wermgr.exe'
            - '\conhost.exe' # csrss.exe, certutil.exe
            - '\mmc.exe'     # eventvwr.exe
            - '\win32calc.exe' # calc.exe
            - '\notepad.exe'
    filter_null:
        Image: null
    condition: selection or ( selection_special and not 1 of filter_* )
falsepositives:
    - Unknown
level: high
```
