```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\MpCmdRun.exe" or tgt.process.image.path contains "\\NisSrv.exe") and (not (tgt.process.image.path contains "C:\\Program Files (x86)\\Windows Defender\\" or tgt.process.image.path contains "C:\\Program Files\\Microsoft Security Client\\" or tgt.process.image.path contains "C:\\Program Files\\Windows Defender\\" or tgt.process.image.path contains "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or tgt.process.image.path contains "C:\\Windows\\WinSxS\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Mpclient.DLL Sideloading Via Defender Binaries
id: 7002aa10-b8d4-47ae-b5ba-51ab07e228b9
related:
    - id: 418dc89a-9808-4b87-b1d7-e5ae0cb6effc
      type: similar
status: test
description: Detects potential sideloading of "mpclient.dll" by Windows Defender processes ("MpCmdRun" and "NisSrv") from their non-default directory.
references:
    - https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool
author: Bhabesh Raj
date: 2022-08-01
modified: 2023-08-04
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\MpCmdRun.exe'
            - '\NisSrv.exe'
    filter_main_known_locations:
        Image|startswith:
            - 'C:\Program Files (x86)\Windows Defender\'
            - 'C:\Program Files\Microsoft Security Client\'
            - 'C:\Program Files\Windows Defender\'
            - 'C:\ProgramData\Microsoft\Windows Defender\Platform\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
