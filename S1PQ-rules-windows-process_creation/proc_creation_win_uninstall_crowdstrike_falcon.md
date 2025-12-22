```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\WindowsSensor.exe" and tgt.process.cmdline contains " /uninstall" and tgt.process.cmdline contains " /quiet"))
```


# Original Sigma Rule:
```yaml
title: Uninstall Crowdstrike Falcon Sensor
id: f0f7be61-9cf5-43be-9836-99d6ef448a18
status: test
description: Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
author: frack113
date: 2021-07-12
modified: 2023-03-09
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\WindowsSensor.exe'
            - ' /uninstall'
            - ' /quiet'
    condition: selection
falsepositives:
    - Administrator might leverage the same command line for debugging or other purposes. However this action must be always investigated
level: high
```
