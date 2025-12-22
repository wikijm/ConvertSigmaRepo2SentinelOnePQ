```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\AppData\\Local\\Apps\\2.0\\" and (tgt.process.image.path contains "\\calc.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\explorer.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\nltest.exe" or tgt.process.image.path contains "\\notepad.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\werfault.exe" or tgt.process.image.path contains "\\wscript.exe")))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Child Process Of ClickOnce Application
id: 67bc0e75-c0a9-4cfc-8754-84a505b63c04
status: test
description: Detects potentially suspicious child processes of a ClickOnce deployment application
references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-12
tags:
    - attack.execution
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains: '\AppData\Local\Apps\2.0\'
        Image|endswith:
            # Add more suspicious processes
            - '\calc.exe'
            - '\cmd.exe'
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
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\werfault.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
