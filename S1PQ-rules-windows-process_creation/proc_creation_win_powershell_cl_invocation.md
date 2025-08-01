```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "SyncInvoke ")
```


# Original Sigma Rule:
```yaml
title: Potential Process Execution Proxy Via CL_Invocation.ps1
id: a0459f02-ac51-4c09-b511-b8c9203fc429
status: test
description: Detects calls to "SyncInvoke" that is part of the "CL_Invocation.ps1" script to proxy execution using "System.Diagnostics.Process"
references:
    - https://lolbas-project.github.io/lolbas/Scripts/Cl_invocation/
    - https://twitter.com/bohops/status/948061991012327424
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova
date: 2020-10-14
modified: 2023-08-17
tags:
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Note: As this function is usually called from within powershell, classical process creation even would not catch it. This will only catch inline calls via "-Command" or "-ScriptBlock" flags for example.
        CommandLine|contains: 'SyncInvoke '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
