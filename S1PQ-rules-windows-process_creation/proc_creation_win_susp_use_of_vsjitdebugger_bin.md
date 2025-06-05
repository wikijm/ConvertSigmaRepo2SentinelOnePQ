```sql
// Translated content (automatically translated on 05-06-2025 02:04:50):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\vsjitdebugger.exe" and (not (tgt.process.image.path="*\vsimmersiveactivatehelper*.exe" or tgt.process.image.path contains "\devenv.exe"))))
```


# Original Sigma Rule:
```yaml
title: Malicious PE Execution by Microsoft Visual Studio Debugger
id: 15c7904e-6ad1-4a45-9b46-5fb25df37fd2
status: test
description: |
  There is an option for a MS VS Just-In-Time Debugger "vsjitdebugger.exe" to launch specified executable and attach a debugger.
  This option may be used adversaries to execute malicious code by signed verified binary.
  The debugger is installed alongside with Microsoft Visual Studio package.
references:
    - https://twitter.com/pabraeken/status/990758590020452353
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Vsjitdebugger/
    - https://learn.microsoft.com/en-us/visualstudio/debugger/debug-using-the-just-in-time-debugger?view=vs-2019
author: Agro (@agro_sev), Ensar Şamil (@sblmsrsn), oscd.community
date: 2020-10-14
modified: 2022-10-09
tags:
    - attack.t1218
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\vsjitdebugger.exe'
    reduction1:
        Image|endswith: '\vsimmersiveactivatehelper*.exe'
    reduction2:
        Image|endswith: '\devenv.exe'
    condition: selection and not (reduction1 or reduction2)
falsepositives:
    - The process spawned by vsjitdebugger.exe is uncommon.
level: medium
```
