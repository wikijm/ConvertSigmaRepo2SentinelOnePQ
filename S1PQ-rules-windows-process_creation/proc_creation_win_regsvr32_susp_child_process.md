```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\regsvr32.exe" and (tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\explorer.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\nltest.exe" or tgt.process.image.path contains "\\notepad.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\werfault.exe" or tgt.process.image.path contains "\\wscript.exe")) and (not (tgt.process.image.path contains "\\werfault.exe" and tgt.process.cmdline contains " -u -p "))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Child Process Of Regsvr32
id: 6f0947a4-1c5e-4e0d-8ac7-53159b8f23ca
related:
    - id: 8e2b24c9-4add-46a0-b4bb-0057b4e6187d
      type: obsolete
status: test
description: Detects potentially suspicious child processes of "regsvr32.exe".
references:
    - https://redcanary.com/blog/intelligence-insights-april-2022/
    - https://www.echotrail.io/insights/search/regsvr32.exe
    - https://www.ired.team/offensive-security/code-execution/t1117-regsvr32-aka-squiblydoo
author: elhoim, Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-05-05
modified: 2023-05-26
tags:
    - attack.defense-evasion
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\regsvr32.exe'
        Image|endswith:
            - '\calc.exe'
            - '\cscript.exe'
            - '\explorer.exe'
            - '\mshta.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\nltest.exe'
            - '\notepad.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\reg.exe'
            - '\schtasks.exe'
            - '\werfault.exe'
            - '\wscript.exe'
    filter_main_werfault:
        Image|endswith: '\werfault.exe'
        CommandLine|contains: ' -u -p '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely, but can rarely occur. Apply additional filters accordingly.
level: high
```
