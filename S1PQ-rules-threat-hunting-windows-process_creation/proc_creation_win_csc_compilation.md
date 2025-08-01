```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\csc.exe" and tgt.process.cmdline contains "/noconfig /fullpaths @"))
```


# Original Sigma Rule:
```yaml
title: Dynamic .NET Compilation Via Csc.EXE - Hunting
id: acf2807c-805b-4042-aab9-f86b6ba9cb2b
related:
    - id: dcaa3f04-70c3-427a-80b4-b870d73c94c4
      type: derived
status: test
description: Detects execution of "csc.exe" to compile .NET code. Attackers often leverage this to compile code on the fly and use it in other stages.
references:
    - https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
    - https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
    - https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
    - https://twitter.com/gN3mes1s/status/1206874118282448897
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-08-02
tags:
    - attack.defense-evasion
    - attack.t1027.004
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\csc.exe'
        CommandLine|contains: '/noconfig /fullpaths @'
    condition: selection
falsepositives:
    - Many legitimate applications make use of dynamic compilation. Use this rule to hunt for anomalies
level: medium
```
