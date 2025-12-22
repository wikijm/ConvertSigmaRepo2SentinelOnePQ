```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\Serv-U.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\msiexec.exe" or tgt.process.image.path contains "\\forfiles.exe" or tgt.process.image.path contains "\\scriptrunner.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Serv-U Process Pattern
id: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
status: test
description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
references:
    - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
author: Florian Roth (Nextron Systems)
date: 2021-07-14
modified: 2022-07-14
tags:
    - attack.credential-access
    - attack.t1555
    - cve.2021-35211
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\Serv-U.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\schtasks.exe'
            - '\regsvr32.exe'
            - '\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
    condition: selection
falsepositives:
    - Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution
level: high
```
