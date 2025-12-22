```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.displayName contains "SharpHound" or tgt.process.displayName contains "SharpHound" or (tgt.process.publisher contains "SpecterOps" or tgt.process.publisher contains "evil corp") or (tgt.process.image.path contains "\\Bloodhound.exe" or tgt.process.image.path contains "\\SharpHound.exe")) or (tgt.process.cmdline contains " -CollectionMethod All " or tgt.process.cmdline contains " --CollectionMethods Session " or tgt.process.cmdline contains " --Loop --Loopduration " or tgt.process.cmdline contains " --PortScanTimeout " or tgt.process.cmdline contains ".exe -c All -d " or tgt.process.cmdline contains "Invoke-Bloodhound" or tgt.process.cmdline contains "Get-BloodHoundData") or (tgt.process.cmdline contains " -JsonFolder " and tgt.process.cmdline contains " -ZipFileName ") or (tgt.process.cmdline contains " DCOnly " and tgt.process.cmdline contains " --NoSaveCache ")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Bloodhound/Sharphound Execution
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
status: test
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
author: Florian Roth (Nextron Systems)
date: 2019-12-20
modified: 2023-02-04
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1482
    - attack.t1069.001
    - attack.t1069.002
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Product|contains: 'SharpHound'
        - Description|contains: 'SharpHound'
        - Company|contains:
              - 'SpecterOps'
              - 'evil corp'
        - Image|contains:
              - '\Bloodhound.exe'
              - '\SharpHound.exe'
    selection_cli_1:
        CommandLine|contains:
            - ' -CollectionMethod All '
            - ' --CollectionMethods Session '
            - ' --Loop --Loopduration '
            - ' --PortScanTimeout '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection_cli_2:
        CommandLine|contains|all:
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection_cli_3:
        CommandLine|contains|all:
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of selection_*
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high
```
