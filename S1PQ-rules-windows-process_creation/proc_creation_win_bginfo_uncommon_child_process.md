```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\bginfo.exe" or src.process.image.path contains "\bginfo64.exe"))
```


# Original Sigma Rule:
```yaml
title: Uncommon Child Process Of BgInfo.EXE
id: aaf46cdc-934e-4284-b329-34aa701e3771
related:
    - id: 811f459f-9231-45d4-959a-0266c6311987
      type: similar
status: test
description: Detects uncommon child processes of "BgInfo.exe" which could be a sign of potential abuse of the binary to proxy execution via external VBScript
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Bginfo/
    - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
author: Nasreddine Bencherchali (Nextron Systems), Beyu Denis, oscd.community
date: 2019-10-26
modified: 2023-08-16
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
    selection:
        ParentImage|endswith:
            - '\bginfo.exe'
            - '\bginfo64.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
