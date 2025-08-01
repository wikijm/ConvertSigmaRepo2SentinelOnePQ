```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\bginfo.exe" or src.process.image.path contains "\bginfo64.exe") and ((tgt.process.image.path contains "\calc.exe" or tgt.process.image.path contains "\cmd.exe" or tgt.process.image.path contains "\cscript.exe" or tgt.process.image.path contains "\mshta.exe" or tgt.process.image.path contains "\notepad.exe" or tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe" or tgt.process.image.path contains "\wscript.exe") or (tgt.process.image.path contains "\AppData\Local\" or tgt.process.image.path contains "\AppData\Roaming\" or tgt.process.image.path contains ":\Users\Public\" or tgt.process.image.path contains ":\Temp\" or tgt.process.image.path contains ":\Windows\Temp\" or tgt.process.image.path contains ":\PerfLogs\"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Child Process Of BgInfo.EXE
id: 811f459f-9231-45d4-959a-0266c6311987
related:
    - id: aaf46cdc-934e-4284-b329-34aa701e3771
      type: similar
status: test
description: Detects suspicious child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
    - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-16
tags:
    - attack.execution
    - attack.t1059.005
    - attack.defense-evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\bginfo.exe'
            - '\bginfo64.exe'
    selection_child:
        - Image|endswith:
              - '\calc.exe'
              - '\cmd.exe'
              - '\cscript.exe'
              - '\mshta.exe'
              - '\notepad.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wscript.exe'
        - Image|contains:
              - '\AppData\Local\'
              - '\AppData\Roaming\'
              - ':\Users\Public\'
              - ':\Temp\'
              - ':\Windows\Temp\'
              - ':\PerfLogs\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
