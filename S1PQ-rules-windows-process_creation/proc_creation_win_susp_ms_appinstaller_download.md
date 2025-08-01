```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline="*ms-appinstaller://*source=*" and tgt.process.cmdline contains "http"))
```


# Original Sigma Rule:
```yaml
title: Potential File Download Via MS-AppInstaller Protocol Handler
id: 180c7c5c-d64b-4a63-86e9-68910451bc8b
related:
    - id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a
      type: derived
status: test
description: |
    Detects usage of the "ms-appinstaller" protocol handler via command line to potentially download arbitrary files via AppInstaller.EXE
    The downloaded files are temporarly stored in ":\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\<RANDOM-8-CHAR-DIRECTORY>"
references:
    - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: 2023-11-09
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'ms-appinstaller://?source='
            - 'http'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
