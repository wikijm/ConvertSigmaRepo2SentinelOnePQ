```sql
// Translated content (automatically translated on 15-10-2024 01:20:01):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\powershell.exe" and (tgt.process.cmdline contains "http://127.0.0.1" and tgt.process.cmdline contains "%{(IRM $_)}" and tgt.process.cmdline contains ".SubString.ToString()[67,72,64]-Join" and tgt.process.cmdline contains "Import-Module")))
```


# Original Sigma Rule:
```yaml
title: Obfuscated PowerShell OneLiner Execution
id: 44e24481-6202-4c62-9127-5a0ae8e3fe3d
status: test
description: Detects the execution of a specific OneLiner to download and execute powershell modules in memory.
author: '@Kostastsale, @TheDFIRReport'
references:
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
    - https://gist.github.com/mgeeky/3b11169ab77a7de354f4111aa2f0df38
date: 2022-05-09
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1059.001
    - attack.t1562.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'http://127.0.0.1'
            - '%{(IRM $_)}'
            - '.SubString.ToString()[67,72,64]-Join'
            - 'Import-Module'
    condition: selection
falsepositives:
    - Unknown
level: high
```
