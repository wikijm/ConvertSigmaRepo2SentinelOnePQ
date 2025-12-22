```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\baaupdate.exe" and (tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious BitLocker Access Agent Update Utility Execution
id: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512
related:
    - id: 6e8fe0a8-ba0b-4a93-8f9e-82657e7a5984 # BaaUpdate.exe Suspicious DLL Load
      type: similar
status: experimental
description: |
    Detects the execution of the BitLocker Access Agent Update Utility (baaupdate.exe) which is not a common parent process for other processes.
    Suspicious child processes spawned by baaupdate.exe could indicate an attempt at lateral movement via BitLocker DCOM & COM Hijacking.
references:
    - https://github.com/rtecCyberSec/BitlockMove
author: andrewdanis, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-18
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\baaupdate.exe'
        Image|endswith:
            - '\bitsadmin.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
