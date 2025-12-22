```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\waveedit.dll" and (not ((src.process.image.path in ("C:\\Program Files (x86)\\Nero\\Nero Apps\\Nero WaveEditor\\waveedit.exe","C:\\Program Files\\Nero\\Nero Apps\\Nero WaveEditor\\waveedit.exe")) and (module.path contains "C:\\Program Files (x86)\\Nero\\Nero Apps\\Nero WaveEditor\\" or module.path contains "C:\\Program Files\\Nero\\Nero Apps\\Nero WaveEditor\\")))))
```


# Original Sigma Rule:
```yaml
title: Potential Waveedit.DLL Sideloading
id: 71b31e99-9ad0-47d4-aeb5-c0ca3928eeeb
status: test
description: Detects potential DLL sideloading of "waveedit.dll", which is part of the Nero WaveEditor audio editing software.
references:
    - https://www.trendmicro.com/en_us/research/23/f/behind-the-scenes-unveiling-the-hidden-workings-of-earth-preta.html
author: X__Junior (Nextron Systems)
date: 2023-06-14
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\waveedit.dll'
    filter_main_legit_path:
        Image:
            - 'C:\Program Files (x86)\Nero\Nero Apps\Nero WaveEditor\waveedit.exe'
            - 'C:\Program Files\Nero\Nero Apps\Nero WaveEditor\waveedit.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Nero\Nero Apps\Nero WaveEditor\'
            - 'C:\Program Files\Nero\Nero Apps\Nero WaveEditor\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
