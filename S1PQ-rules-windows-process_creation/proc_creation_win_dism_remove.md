```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\DismHost.exe" and (src.process.cmdline contains "/Online" and src.process.cmdline contains "/Disable-Feature")) or (tgt.process.image.path contains "\\Dism.exe" and (tgt.process.cmdline contains "/Online" and tgt.process.cmdline contains "/Disable-Feature"))))
```


# Original Sigma Rule:
```yaml
title: Dism Remove Online Package
id: 43e32da2-fdd0-4156-90de-50dfd62636f9
status: test
description: Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-26---disable-windows-defender-with-dism
    - https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html
author: frack113
date: 2022-01-16
modified: 2022-08-26
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_dismhost:
        Image|endswith: '\DismHost.exe'
        ParentCommandLine|contains|all:
            - '/Online'
            - '/Disable-Feature'
            # - '/FeatureName:'
            # - '/Remove'
            # /NoRestart
            # /quiet
    selection_dism:
        Image|endswith: '\Dism.exe'
        CommandLine|contains|all:
            - '/Online'
            - '/Disable-Feature'
            # - '/FeatureName:'
            # - '/Remove'
            # /NoRestart
            # /quiet
    condition: 1 of selection_*
falsepositives:
    - Legitimate script
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_dism_remove/info.yml
simulation:
    - type: atomic-red-team
      name: Disable Windows Defender with DISM
      technique: T1562.001
      atomic_guid: 871438ac-7d6e-432a-b27d-3e7db69faf58
```
