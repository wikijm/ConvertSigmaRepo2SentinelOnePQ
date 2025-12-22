```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\mmc.exe" and ((tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\regsvr32.exe") or tgt.process.image.path contains "\\BITSADMIN")))
```


# Original Sigma Rule:
```yaml
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: test
description: Detects a Windows command line executable started from MMC
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
author: Karneades, Swisscom CSIRT
date: 2019-08-05
modified: 2022-07-14
tags:
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        ParentImage|endswith: '\mmc.exe'
    selection2:
        - Image|endswith:
              - '\cmd.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wscript.exe'
              - '\cscript.exe'
              - '\sh.exe'
              - '\bash.exe'
              - '\reg.exe'
              - '\regsvr32.exe'
        - Image|contains: '\BITSADMIN'
    condition: all of selection*
level: high
```
