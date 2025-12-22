```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\DefaultPack.exe")
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Process Of Defaultpack.EXE
id: b2309017-4235-44fe-b5af-b15363011957
status: test
description: Detects uncommon child processes of "DefaultPack.EXE" binary as a proxy to launch other programs
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
    - https://www.echotrail.io/insights/search/defaultpack.exe
author: frack113
date: 2022-12-31
modified: 2024-04-22
tags:
    - attack.t1218
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DefaultPack.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
