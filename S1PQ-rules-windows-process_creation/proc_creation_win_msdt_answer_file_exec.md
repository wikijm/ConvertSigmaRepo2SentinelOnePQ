```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\msdt.exe" and tgt.process.cmdline contains "\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml" and (tgt.process.cmdline contains " -af " or tgt.process.cmdline contains " /af " or tgt.process.cmdline contains " –af " or tgt.process.cmdline contains " —af " or tgt.process.cmdline contains " ―af ")) and (not src.process.image.path contains "\\pcwrun.exe")))
```


# Original Sigma Rule:
```yaml
title: MSDT Execution Via Answer File
id: 9c8c7000-3065-44a8-a555-79bcba5d9955
status: test
description: |
    Detects execution of "msdt.exe" using an answer file which is simulating the legitimate way of calling msdt via "pcwrun.exe" (For example from the compatibility tab).
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Msdt/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-13
modified: 2025-10-29
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msdt.exe'
        CommandLine|contains: '\WINDOWS\diagnostics\index\PCWDiagnostic.xml'
        CommandLine|contains|windash: ' -af '
    filter_main_pcwrun:
        ParentImage|endswith: '\pcwrun.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Possible undocumented parents of "msdt" other than "pcwrun".
level: high
```
