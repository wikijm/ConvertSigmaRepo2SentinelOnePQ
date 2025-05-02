```sql
// Translated content (automatically translated on 02-05-2025 02:00:24):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\SndVol.exe" and (not (tgt.process.image.path contains "\rundll32.exe" and tgt.process.cmdline contains " shell32.dll,Control_RunDLL "))))
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Processes Of SndVol.exe
id: ba42babc-0666-4393-a4f7-ceaf5a69191e
status: test
description: Detects potentially uncommon child processes of SndVol.exe (the Windows volume mixer)
references:
    - https://twitter.com/Max_Mal_/status/1661322732456353792
author: X__Junior (Nextron Systems)
date: 2023-06-09
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\SndVol.exe'
    filter_main_rundll32:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: ' shell32.dll,Control_RunDLL '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
