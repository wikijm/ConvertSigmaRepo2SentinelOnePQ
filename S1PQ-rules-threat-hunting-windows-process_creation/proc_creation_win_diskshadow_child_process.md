```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\diskshadow.exe" and (not tgt.process.image.path contains ":\Windows\System32\WerFault.exe")))
```


# Original Sigma Rule:
```yaml
title: Diskshadow Child Process Spawned
id: 56b1dde8-b274-435f-a73a-fb75eb81262a
related:
    - id: fa1a7e52-3d02-435b-81b8-00da14dd66c1 # Diskshadow Script Mode - Execution From Potential Suspicious Location
      type: similar
    - id: 1dde5376-a648-492e-9e54-4241dd9b0c7f # Diskshadow Script Mode - Uncommon Script Extension Execution
      type: similar
    - id: 9f546b25-5f12-4c8d-8532-5893dcb1e4b8 # Potentially Suspicious Child Process Of DiskShadow.EXE
      type: similar
    - id: 0c2f8629-7129-4a8a-9897-7e0768f13ff2 # Diskshadow Script Mode Execution
      type: similar
status: test
description: Detects any child process spawning from "Diskshadow.exe". This could be due to executing Diskshadow in interpreter mode or script mode and using the "exec" flag to launch other applications.
references:
    - https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
    - https://medium.com/@cyberjyot/lolbin-execution-via-diskshadow-f6ff681a27a4
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow
author: Harjot Singh @cyb3rjy0t
date: 2023-09-15
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.execution
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\diskshadow.exe'
    filter_main_werfault:
        Image|endswith: ':\Windows\System32\WerFault.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Likely from legitimate usage of Diskshadow in Interpreter mode.
level: medium
```
