```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\winlogon.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\wt.exe") and (tgt.process.cmdline contains "sethc.exe" or tgt.process.cmdline contains "utilman.exe" or tgt.process.cmdline contains "osk.exe" or tgt.process.cmdline contains "Magnify.exe" or tgt.process.cmdline contains "Narrator.exe" or tgt.process.cmdline contains "DisplaySwitch.exe")))
```


# Original Sigma Rule:
```yaml
title: Sticky Key Like Backdoor Execution
id: 2fdefcb3-dbda-401e-ae23-f0db027628bc
related:
    - id: baca5663-583c-45f9-b5dc-ea96a22ce542
      type: derived
status: test
description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
references:
    - https://learn.microsoft.com/en-us/archive/blogs/jonathantrull/detecting-sticky-key-backdoors
author: Florian Roth (Nextron Systems), @twjackomo, Jonhnathan Ribeiro, oscd.community
date: 2018-03-15
modified: 2023-03-07
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1546.008
    - car.2014-11-003
    - car.2014-11-008
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\winlogon.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
            - '\wt.exe'
        CommandLine|contains:
            - 'sethc.exe'
            - 'utilman.exe'
            - 'osk.exe'
            - 'Magnify.exe'
            - 'Narrator.exe'
            - 'DisplaySwitch.exe'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
