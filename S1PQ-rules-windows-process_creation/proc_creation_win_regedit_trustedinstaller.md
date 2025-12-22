```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\regedit.exe" and (src.process.image.path contains "\\TrustedInstaller.exe" or src.process.image.path contains "\\ProcessHacker.exe")))
```


# Original Sigma Rule:
```yaml
title: Regedit as Trusted Installer
id: 883835a7-df45-43e4-bf1d-4268768afda4
status: test
description: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth (Nextron Systems)
date: 2021-05-27
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regedit.exe'
        ParentImage|endswith:
            - '\TrustedInstaller.exe'
            - '\ProcessHacker.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
