```sql
// Translated content (automatically translated on 10-11-2025 01:21:01):
event.type="Module Load" and (endpoint.os="windows" and (src.process.image.path contains "\\spoolsv.exe" and (module.path contains "\\Windows\\System32\\spool\\drivers\\x64\\3\\" or module.path contains "\\Windows\\System32\\spool\\drivers\\x64\\4\\") and module.path contains ".dll"))
```


# Original Sigma Rule:
```yaml
title: Windows Spooler Service Suspicious Binary Load
id: 02fb90de-c321-4e63-a6b9-25f4b03dfd14
status: test
description: Detect DLL Load from Spooler Service backup folder
references:
    - https://web.archive.org/web/20210629055600/https://github.com/hhlxf/PrintNightmare/
    - https://github.com/ly4k/SpoolFool
author: FPT.EagleEye, Thomas Patzke (improvements)
date: 2021-06-29
modified: 2022-06-02
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574
    - cve.2021-1675
    - cve.2021-34527
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\spoolsv.exe'
        ImageLoaded|contains:
            - '\Windows\System32\spool\drivers\x64\3\'
            - '\Windows\System32\spool\drivers\x64\4\'
        ImageLoaded|endswith: '.dll'
    condition: selection
falsepositives:
    - Loading of legitimate driver
level: informational
```
