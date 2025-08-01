```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (src.process.image.path contains "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_" and src.process.image.path contains "\AppInstaller.exe"))
```


# Original Sigma Rule:
```yaml
title: AppX Package Installation Attempts Via AppInstaller.EXE
id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a
related:
    - id: 180c7c5c-d64b-4a63-86e9-68910451bc8b
      type: derived
status: test
description: |
    Detects DNS queries made by "AppInstaller.EXE". The AppInstaller is the default handler for the "ms-appinstaller" URI. It attempts to load/install a package from the referenced URL
references:
    - https://twitter.com/notwhickey/status/1333900137232523264
    - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
author: frack113
date: 2021-11-24
modified: 2023-11-09
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        Image|startswith: 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_'
        Image|endswith: '\AppInstaller.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
