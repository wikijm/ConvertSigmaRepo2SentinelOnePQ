```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\DllHost.exe" and (src.process.cmdline contains " /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" or src.process.cmdline contains " /Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}" or src.process.cmdline contains " /Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}" or src.process.cmdline contains " /Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}" or src.process.cmdline contains " /Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}") and (tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288"))))
```


# Original Sigma Rule:
```yaml
title: CMSTP UAC Bypass via COM Object Access
id: 4b60e6f2-bf39-47b4-b4ea-398e33cfe253
status: stable
description: Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects (e.g. UACMe ID of 41, 43, 58 or 65)
references:
    - https://web.archive.org/web/20190720093911/http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
    - https://twitter.com/hFireF0X/status/897640081053364225
    - https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf
    - https://github.com/hfiref0x/UACME
author: Nik Seetharaman, Christian Burkard (Nextron Systems)
date: 2019-07-31
modified: 2024-12-01
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
    - attack.t1218.003
    - attack.g0069
    - car.2019-04-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DllHost.exe'
        ParentCommandLine|contains:
            - ' /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}' # cmstplua.dll
            - ' /Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}' # CMLUAUTIL
            - ' /Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}' # EditionUpgradeManagerObj.dll
            - ' /Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}' # colorui.dll
            - ' /Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}' # wscui.cpl
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high
```
