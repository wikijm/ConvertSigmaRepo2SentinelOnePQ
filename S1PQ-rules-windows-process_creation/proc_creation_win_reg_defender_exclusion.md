```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\reg.exe" and (tgt.process.cmdline contains "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" or tgt.process.cmdline contains "SOFTWARE\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths") and (tgt.process.cmdline contains "ADD " and tgt.process.cmdline contains "/t " and tgt.process.cmdline contains "REG_DWORD " and tgt.process.cmdline contains "/v " and tgt.process.cmdline contains "/d " and tgt.process.cmdline contains "0")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Windows Defender Folder Exclusion Added Via Reg.EXE
id: 48917adc-a28e-4f5d-b729-11e75da8941f
status: test
description: Detects the usage of "reg.exe" to add Defender folder exclusions. Qbot has been seen using this technique to add exclusions for folders within AppData and ProgramData.
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
    - https://redcanary.com/threat-detection-report/threats/qbot/
author: frack113
date: 2022-02-13
modified: 2023-02-04
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - 'SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
            - 'SOFTWARE\Microsoft\Microsoft Antimalware\Exclusions\Paths'
        CommandLine|contains|all:
            - 'ADD '
            - '/t '
            - 'REG_DWORD '
            - '/v '
            - '/d '
            - '0'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
