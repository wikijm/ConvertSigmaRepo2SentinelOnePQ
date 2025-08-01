```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\hxtsr.exe" and (not (tgt.process.image.path contains ":\program files\windowsapps\microsoft.windowscommunicationsapps_" and tgt.process.image.path contains "\hxtsr.exe"))))
```


# Original Sigma Rule:
```yaml
title: Potential Fake Instance Of Hxtsr.EXE Executed
id: 4e762605-34a8-406d-b72e-c1a089313320
status: test
description: |
    HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.
    HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files".
    Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe
references:
    - Internal Research
author: Sreeman
date: 2020-04-17
modified: 2024-02-08
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    product: windows
    category: process_creation
detection:
    # TODO: Link this to the more generic system process rule
    selection:
        Image|endswith: '\hxtsr.exe'
    filter_main_hxtsr:
        Image|contains: ':\program files\windowsapps\microsoft.windowscommunicationsapps_'
        Image|endswith: '\hxtsr.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
