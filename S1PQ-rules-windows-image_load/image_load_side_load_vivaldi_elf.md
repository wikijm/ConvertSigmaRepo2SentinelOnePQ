```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vivaldi_elf.dll" and (not (src.process.image.path contains "\\Vivaldi\\Application\\vivaldi.exe" and module.path contains "\\Vivaldi\\Application\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Vivaldi_elf.DLL Sideloading
id: 2092cacb-d77b-4f98-ab0d-32b32f99a054
status: test
description: Detects potential DLL sideloading of "vivaldi_elf.dll"
references:
    - https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/
author: X__Junior (Nextron Systems)
date: 2023-08-03
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
        ImageLoaded|endswith: '\vivaldi_elf.dll'
    filter_main_legit_path:
        Image|endswith: '\Vivaldi\Application\vivaldi.exe'
        ImageLoaded|contains: '\Vivaldi\Application\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
