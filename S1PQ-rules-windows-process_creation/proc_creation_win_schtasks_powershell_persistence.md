```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="C:\WINDOWS\System32\svchost.exe" and (src.process.cmdline contains "-k netsvcs" and src.process.cmdline contains "-s Schedule") and (tgt.process.cmdline contains " -windowstyle hidden" or tgt.process.cmdline contains " -w hidden" or tgt.process.cmdline contains " -ep bypass" or tgt.process.cmdline contains " -noni")))
```


# Original Sigma Rule:
```yaml
title: Potential Persistence Via Powershell Search Order Hijacking - Task
id: b66474aa-bd92-4333-a16c-298155b120df
related:
    - id: 6e8811ee-90ba-441e-8486-5653e68b2299
      type: similar
status: test
description: Detects suspicious powershell execution via a schedule task where the command ends with an suspicious flags to hide the powershell instance instead of executeing scripts or commands. This could be a sign of persistence via PowerShell "Get-Variable" technique as seen being used in Colibri Loader
references:
    - https://blog.malwarebytes.com/threat-intelligence/2022/04/colibri-loader-combines-task-scheduler-and-powershell-in-clever-persistence-technique/
author: pH-T (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022-04-08
modified: 2023-02-03
tags:
    - attack.execution
    - attack.persistence
    - attack.t1053.005
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage: 'C:\WINDOWS\System32\svchost.exe'
        ParentCommandLine|contains|all:
            - '-k netsvcs'
            - '-s Schedule'
        CommandLine|endswith:
            - ' -windowstyle hidden'
            - ' -w hidden'
            - ' -ep bypass'
            - ' -noni'
    condition: selection
falsepositives:
    - Unknown
level: high
```
